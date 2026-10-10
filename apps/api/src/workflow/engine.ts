import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Db } from '../store/db';
import { ActionType, ExecutionStep, WorkflowExecution, DryRunPlan } from '../store/models';
import { WorkflowService, DESTRUCTIVE_ACTIONS } from './workflow.service';
import { ApprovalsService } from '../approvals/approvals.service';
import { ApprovalSigner } from '../approvals/signer';
import { DryRunService } from '../remediation/dryrun.service';
import { AuditTrail } from '../audit/audit-trail';
import { JOB_QUEUE, JobQueue } from '../queue/queue';
import { ApprovalProof } from './ports';
import { newId, now } from '../common/ids';
import { EXECUTION_LOCK, ExecutionLock } from './lock';
import { redact } from '../common/mask';

/** A failure that retrying cannot fix (e.g. failed healthcheck → already rolled back). */
export class TerminalStepError extends Error {}

export interface StepCtx {
  orgId: string; execution: WorkflowExecution; step: ExecutionStep; idempotencyKey: string;
  input: Record<string, unknown>; outputs: Record<string, Record<string, unknown> | undefined>;
  plan?: DryRunPlan; proof?: ApprovalProof;
}
export type ActionHandler = (c: StepCtx) => Promise<Record<string, unknown>>;

const MAX_ATTEMPTS = 5;

@Injectable()
export class WorkflowEngine implements OnModuleInit {
  private log = new Logger('Engine');
  private handlers = new Map<ActionType, ActionHandler>();

  constructor(
    private db: Db, private workflows: WorkflowService, private approvals: ApprovalsService, private signer: ApprovalSigner,
    private dryrun: DryRunService, private audit: AuditTrail, @Inject(JOB_QUEUE) private queue: JobQueue, @Inject(EXECUTION_LOCK) private lock: ExecutionLock,
  ) {}

  onModuleInit() { this.queue.process((j) => this.advance(j.orgId, j.executionId)); }

  register(action: ActionType, h: ActionHandler) { this.handlers.set(action, h); }

  async start(orgId: string, key: string, context: Record<string, unknown>, actor: string, incidentId?: string): Promise<WorkflowExecution> {
    const wf = this.workflows.resolve(orgId, key);
    const ex: WorkflowExecution = {
      id: newId('exe'), orgId, workflowId: wf.id, workflowKey: key, workflowVersion: wf.version, status: 'queued',
      context: { ...context, requestedBy: actor }, incidentId, createdAt: now(), updatedAt: now(),
      steps: wf.steps.map((s) => ({ name: s.name, action: s.action, destructive: !!s.destructive || DESTRUCTIVE_ACTIONS.has(s.action), status: 'pending', attempts: 0 })),
    };
    this.db.executions.put(ex);
    this.audit.append(orgId, actor, 'execution.started', { executionId: ex.id, workflow: key, version: wf.version, context });
    await this.queue.enqueue({ orgId, executionId: ex.id });
    return ex;
  }

  /** Re-entrant & resumable: derives everything from persisted state, so a crashed worker can simply be re-run. */
  async advance(orgId: string, executionId: string): Promise<void> {
    // Throws LockBusyError when another worker owns the execution → the queue retries with backoff (no lost wake-ups).
    const release = await this.lock.acquire(`${orgId}:${executionId}`, 120_000);
    try { await this.loop(orgId, executionId); } finally { await release(); }
  }

  private save(orgId: string, id: string, fn: (e: WorkflowExecution) => void) {
    return this.db.executions.update(orgId, id, (e) => { fn(e); e.updatedAt = now(); });
  }

  private async loop(orgId: string, id: string) {
    let ex = this.db.executions.get(orgId, id);
    if (!ex || ['succeeded', 'failed', 'rejected'].includes(ex.status)) return;
    ex = this.save(orgId, id, (e) => { e.status = 'running'; });

    for (let i = 0; i < ex.steps.length; i++) {
      const step = ex.steps[i];
      if (step.status === 'succeeded' || step.status === 'skipped') continue;

      let plan: DryRunPlan | undefined, proof: ApprovalProof | undefined;
      if (step.destructive) {
        const gate = await this.gate(ex, step);
        if (gate.kind === 'pause') return;
        if (gate.kind === 'rejected') return;
        if (gate.kind === 'terminal') { this.failTerminal(orgId, id, i, gate.reason); return; }
        ({ plan, proof } = gate);
      }

      this.save(orgId, id, (e) => { e.steps[i].status = 'running'; e.steps[i].attempts++; e.steps[i].startedAt ??= now(); });
      const handler = this.handlers.get(step.action);
      try {
        if (!handler) throw new TerminalStepError(`no handler for ${step.action}`);
        const outputs = Object.fromEntries(ex.steps.map((s) => [s.name, s.output]));
        const fresh = this.db.executions.get(orgId, id)!;
        const out = await handler({ orgId, execution: fresh, step: fresh.steps[i], idempotencyKey: `${id}:${step.name}`, input: fresh.context, outputs, plan, proof });
        this.save(orgId, id, (e) => { Object.assign(e.steps[i], { status: 'succeeded', output: redact(out), error: undefined, finishedAt: now() }); });
        if (plan) this.db.plans.update(orgId, plan.id, { applied: true });
        this.audit.append(orgId, 'system', 'step.succeeded', { executionId: id, step: step.name, action: step.action, destructive: step.destructive, output: out });
        ex = this.db.executions.get(orgId, id)!;
      } catch (e) {
        const msg = (e as Error).message;
        if (e instanceof TerminalStepError || this.db.executions.get(orgId, id)!.steps[i].attempts >= MAX_ATTEMPTS) { this.failTerminal(orgId, id, i, msg); return; }
        this.save(orgId, id, (x) => { x.steps[i].status = 'failed'; x.steps[i].error = msg; });
        this.log.warn(`step ${step.name} failed (will retry): ${msg}`);
        throw e; // let the queue retry with backoff
      }
    }
    this.save(orgId, id, (e) => { e.status = 'succeeded'; });
    this.audit.append(orgId, 'system', 'execution.succeeded', { executionId: id });
  }

  private failTerminal(orgId: string, id: string, idx: number, reason: string) {
    this.save(orgId, id, (e) => {
      e.status = 'failed';
      e.steps[idx] = { ...e.steps[idx], status: 'failed', error: reason, finishedAt: now() };
      for (let j = idx + 1; j < e.steps.length; j++) if (e.steps[j].status === 'pending') e.steps[j].status = 'skipped';
    });
    this.audit.append(orgId, 'system', 'execution.failed', { executionId: id, step: idx, reason });
  }

  private async gate(ex: WorkflowExecution, step: ExecutionStep): Promise<
    | { kind: 'ok'; plan: DryRunPlan; proof: ApprovalProof } | { kind: 'pause' } | { kind: 'rejected' } | { kind: 'terminal'; reason: string }> {
    const planId = (ex.context['plans'] as Record<string, string> | undefined)?.[step.name];
    const plan = planId ? this.db.plans.get(ex.orgId, planId) : undefined;
    if (!plan) return { kind: 'terminal', reason: `destructive step "${step.name}" has no dry-run plan` };
    if (plan.applied) return { kind: 'terminal', reason: 'plan already applied' };
    if (plan.action !== step.action) return { kind: 'terminal', reason: 'plan action does not match step' };
    if (!this.dryrun.intact(plan)) return { kind: 'terminal', reason: 'plan content changed after it was proposed' };

    const a = this.approvals.request(ex.orgId, ex.id, step.name, plan);
    if (a.status === 'pending') {
      this.save(ex.orgId, ex.id, (e) => {
        const s = e.steps.find((x) => x.name === step.name)!; s.status = 'awaiting_approval'; e.status = 'awaiting_approval';
      });
      return { kind: 'pause' };
    }
    if (a.status === 'rejected') {
      this.save(ex.orgId, ex.id, (e) => {
        e.status = 'rejected';
        let seen = false; for (const s of e.steps) { if (s.name === step.name) { seen = true; s.status = 'skipped'; s.error = 'rejected by SecOps'; } else if (seen && s.status === 'pending') s.status = 'skipped'; }
      });
      this.audit.append(ex.orgId, 'system', 'execution.rejected', { executionId: ex.id, step: step.name });
      return { kind: 'rejected' };
    }
    if (!(await this.signer.verifyApproval(a)) || a.planHash !== plan.planHash) return { kind: 'terminal', reason: 'approval signature invalid or bound to a different plan' };
    return { kind: 'ok', plan, proof: this.signer.toProof(a) };
  }
}
