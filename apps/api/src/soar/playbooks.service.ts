import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { AutomationMode, Condition, Playbook, PlaybookAction, PlaybookActionType, PlaybookRun, RunStep, TriggerType } from '../store/enterprise.models';
import type { Severity } from '../store/models';
import { AuditTrail } from '../audit/audit-trail';
import { ApprovalsService } from '../approvals/approvals.service';
import { ApprovalSigner } from '../approvals/signer';
import { NotificationsService } from '../notifications/notifications.service';
import { CasesService } from '../cases/cases.service';
import { DomainEvent, EventBus } from '../common/events';
import { newId, now, sha256, stableStringify } from '../common/ids';
import { redactString } from '../common/mask';
import { Principal } from '../auth/auth';
import { IamService } from '../iam/iam.service';
import { Metrics } from '../ops/metrics';

export const SAFE_ACTIONS: ReadonlySet<PlaybookActionType> = new Set(['notify', 'create_case', 'create_ticket', 'tag']);
/** What each risky action does if it ever runs for real, and how dangerous that is. Drives the playbook's effective risk level. */
const RISK_OF: Partial<Record<PlaybookActionType, 'medium' | 'high'>> = { propose_endpoint_isolation: 'high', propose_account_lock: 'high', propose_permission_change: 'high', propose_session_revoke: 'medium', propose_config_fix: 'medium', propose_patch_request: 'medium' };
const MODE_RANK: Record<AutomationMode, number> = { OBSERVE: 0, ASSISTED: 1, AUTOMATED: 2 };
const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const ACTIONS = ['create_case', 'create_ticket', 'notify', 'tag', 'propose_account_lock', 'propose_session_revoke', 'propose_endpoint_isolation', 'propose_config_fix', 'propose_patch_request', 'propose_permission_change'] as const;

export interface AutomationSettings { ceiling: AutomationMode; automatedEnabled: boolean; allowedAutoActions: PlaybookActionType[]; maxActionsPerHour: number; killSwitch: boolean; killReason?: string }
export const DEFAULT_AUTOMATION: AutomationSettings = { ceiling: 'ASSISTED', automatedEnabled: false, allowedAutoActions: [], maxActionsPerHour: 10, killSwitch: false };

export const PlaybookSchema = z.object({
  key: z.string().regex(/^[a-z][a-z0-9-]{2,60}$/), name: z.string().min(1).max(150), description: z.string().max(1000).default(''),
  trigger: z.object({ type: z.enum(['signal', 'finding', 'vulnerability', 'exposure', 'identity']), kind: z.string().max(60).optional() }).strict(),
  conditions: z.array(z.object({ field: z.string().regex(/^[\w.]{1,80}$/), op: z.enum(['eq', 'neq', 'gte', 'lte', 'in', 'contains', 'exists']), value: z.unknown().optional() }).strict()).max(20).default([]),
  actions: z.array(z.object({ type: z.enum(ACTIONS), params: z.record(z.string(), z.unknown()).default({}) }).strict()).min(1).max(10),
  owner: z.string().min(1).max(100), riskLevel: z.enum(['low', 'medium', 'high']).default('low'), mode: z.enum(['OBSERVE', 'ASSISTED', 'AUTOMATED']).default('ASSISTED'), enabled: z.boolean().default(true),
}).strict();
export const AutomationSchema = z.object({ ceiling: z.enum(['OBSERVE', 'ASSISTED', 'AUTOMATED']).optional(), automatedEnabled: z.boolean().optional(), allowedAutoActions: z.array(z.enum(ACTIONS)).max(20).optional(), maxActionsPerHour: z.number().int().min(0).max(1000).optional() }).strict();

const get = (o: unknown, path: string): unknown => path.split('.').reduce<unknown>((a, k) => (a && typeof a === 'object' ? (a as Record<string, unknown>)[k] : undefined), o);
const num = (v: unknown) => (typeof v === 'string' && v in SEV_RANK ? SEV_RANK[v] : Number(v));
export function evalCondition(c: Condition, ctx: unknown): boolean {
  const v = get(ctx, c.field);
  switch (c.op) {
    case 'exists': return v !== undefined && v !== null && v !== '';
    case 'eq': return typeof v === 'string' && typeof c.value === 'string' ? v.toLowerCase() === c.value.toLowerCase() : v === c.value;
    case 'neq': return !(typeof v === 'string' && typeof c.value === 'string' ? v.toLowerCase() === c.value.toLowerCase() : v === c.value);
    case 'gte': return Number.isFinite(num(v)) && Number.isFinite(num(c.value)) && num(v) >= num(c.value);
    case 'lte': return Number.isFinite(num(v)) && Number.isFinite(num(c.value)) && num(v) <= num(c.value);
    case 'in': return Array.isArray(c.value) && c.value.some((x) => (typeof x === 'string' && typeof v === 'string' ? x.toLowerCase() === v.toLowerCase() : x === v));
    case 'contains': return Array.isArray(v) ? v.some((x) => String(x).toLowerCase() === String(c.value).toLowerCase()) : typeof v === 'string' && v.toLowerCase().includes(String(c.value ?? '').toLowerCase());
  }
}
/** `{{trigger.title}}` templating. Only dotted paths are resolved; nothing is evaluated. */
export function render(v: unknown, ctx: unknown): unknown {
  if (typeof v === 'string') return redactString(v.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_m, p: string) => { const x = get(ctx, p); return x === undefined || x === null ? '' : String(typeof x === 'object' ? JSON.stringify(x) : x); }));
  if (Array.isArray(v)) return v.map((x) => render(x, ctx));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, render(x, ctx)]));
  return v;
}

/** Port to the outside world for approved/automated risky actions. The only implementation shipped is the lab executor. */
export const SOAR_EXECUTOR = Symbol('SOAR_EXECUTOR');
export interface SoarExecutor { readonly name: string; execute(orgId: string, run: PlaybookRun, step: RunStep): Promise<Record<string, unknown>> }

@Injectable()
export class LabExecutor implements SoarExecutor {
  readonly name = 'lab';
  constructor(private db: Db) {}
  /** Records the effect as it WOULD happen. Idempotent by the step's idempotency key. Nothing outside SentinelMesh is touched. */
  async execute(orgId: string, run: PlaybookRun, step: RunStep) {
    const id = `lab_${sha256(step.idempotencyKey).slice(0, 20)}`;
    const ex = await this.db.labEffects.get(orgId, id);
    if (!ex) await this.db.labEffects.put({ id, orgId, runId: run.id, action: step.action, target: String(step.params['target'] ?? step.params['asset'] ?? step.params['identity'] ?? run.trigger.refId), at: now(), params: step.params });
    return { executor: 'lab', effectId: id, replay: !!ex, note: 'recorded in the lab executor; nothing was changed in any real system' };
  }
}

@Injectable()
export class PlaybooksService implements OnModuleInit {
  constructor(private db: Db, private audit: AuditTrail, private approvals: ApprovalsService, private signer: ApprovalSigner, private notify: NotificationsService, private cases: CasesService, private bus: EventBus,
    private iam: IamService, @Inject(SOAR_EXECUTOR) private executor: SoarExecutor, private metrics: Metrics) {}

  onModuleInit() {
    this.bus.subscribe((e) => this.handle(e));
    this.approvals.onDecision(async (a) => { if (a.stepName.startsWith('step-')) await this.afterDecision(a.orgId, a.executionId, a.stepName, a.status === 'approved'); });
  }

  // ───────── settings ─────────
  async automation(orgId: string): Promise<AutomationSettings> { return { ...DEFAULT_AUTOMATION, ...((await this.setting(orgId, 'automation')) as Partial<AutomationSettings> | undefined) }; }
  private async setting(orgId: string, key: string) { return (await this.db.settings.where(orgId, { key }))[0]?.value; }
  private async setSetting(orgId: string, key: string, value: unknown, by: string) {
    const ex = (await this.db.settings.where(orgId, { key }))[0];
    if (ex) await this.db.settings.update(orgId, ex.id, { value, updatedAt: now(), updatedBy: by });
    else await this.db.settings.createUnique({ id: newId('set'), orgId, key, value, updatedAt: now(), updatedBy: by }, { key });
  }
  async setAutomation(me: Principal, p: z.infer<typeof AutomationSchema>) {
    const cur = await this.automation(me.orgId), next = { ...cur, ...p };
    if (p.automatedEnabled === false && p.ceiling === undefined) { next.ceiling = MODE_RANK[next.ceiling] > 1 ? 'ASSISTED' : next.ceiling; next.allowedAutoActions = []; }   // switching AUTOMATED off drops the ceiling and the allow-list
    if (next.ceiling === 'AUTOMATED' && !next.automatedEnabled) throw new BadRequestException('set automatedEnabled=true explicitly to allow the AUTOMATED ceiling (it is off by default)');
    await this.setSetting(me.orgId, 'automation', next, me.userId);
    await this.audit.append(me.orgId, me.userId, 'soar.automation_changed', { from: cur, to: next });
    return next;
  }
  /** Emergency stop: nothing executes automatically, pending approvals cannot be executed, running work is stopped. */
  async killSwitch(me: Principal, on: boolean, reason: string) {
    const cur = await this.automation(me.orgId);
    await this.setSetting(me.orgId, 'automation', { ...cur, killSwitch: on, killReason: on ? reason : undefined }, me.userId);
    let stopped = 0;
    if (on) for (const r of await this.db.runs.list(me.orgId, (x) => x.status === 'awaiting_approval' || x.status === 'executing')) { await this.stop(me, r.id, `kill switch: ${reason}`); stopped++; }
    await this.audit.append(me.orgId, me.userId, on ? 'soar.kill_switch_on' : 'soar.kill_switch_off', { reason, stopped });
    await this.notify.dispatch(me.orgId, { event: 'soar.kill_switch', severity: 'high', subject: `SOAR kill switch ${on ? 'ENGAGED' : 'released'}`, body: `${me.userId}: ${reason}. ${stopped} run(s) stopped.`, dedupKey: this.notify.dedup(['kill', String(on), me.orgId, new Date().toISOString().slice(0, 13)]) }).catch(() => undefined);
    return { killSwitch: on, stopped };
  }
  private effectiveMode(pb: Playbook, a: AutomationSettings): AutomationMode {
    if (a.killSwitch) return 'OBSERVE';
    let m = MODE_RANK[pb.mode] <= MODE_RANK[a.ceiling] ? pb.mode : a.ceiling;
    if (m === 'AUTOMATED' && !a.automatedEnabled) m = 'ASSISTED';
    return m;
  }

  // ───────── playbook catalogue (immutable versions) ─────────
  async publish(me: Principal, i: z.infer<typeof PlaybookSchema>): Promise<Playbook> {
    const a = await this.automation(me.orgId);
    if (i.mode === 'AUTOMATED' && !a.automatedEnabled) throw new BadRequestException('AUTOMATED mode is disabled for this organisation; an administrator must enable it first');
    const worst = i.actions.reduce<'low' | 'medium' | 'high'>((m, x) => { const r = RISK_OF[x.type] ?? 'low'; return r === 'high' || m === 'high' ? 'high' : r === 'medium' || m === 'medium' ? 'medium' : 'low'; }, 'low');
    const riskLevel = ['low', 'medium', 'high'].indexOf(worst) > ['low', 'medium', 'high'].indexOf(i.riskLevel) ? worst : i.riskLevel;
    for (let attempt = 0; attempt < 5; attempt++) {
      const prev = (await this.db.playbooks.where(me.orgId, { key: i.key })).sort((x, y) => y.version - x.version)[0];
      const pb: Playbook = { id: newId('pbk'), orgId: me.orgId, key: i.key, name: i.name, description: i.description, version: (prev?.version ?? 0) + 1, trigger: i.trigger, conditions: i.conditions as Condition[], actions: i.actions as PlaybookAction[], owner: i.owner, riskLevel, mode: i.mode, enabled: i.enabled, createdAt: now(), createdBy: me.userId };
      const { row, created } = await this.db.playbooks.createUnique(pb, { key: i.key, version: pb.version });
      if (!created) continue;
      await this.setSetting(me.orgId, `playbook-state:${i.key}`, { enabled: i.enabled }, me.userId);
      await this.audit.append(me.orgId, me.userId, 'playbook.published', { key: i.key, version: row.version, mode: i.mode, riskLevel, actions: i.actions.map((x) => x.type) });
      return row;
    }
    throw new ConflictException('could not publish: too much contention');
  }
  private async latest(orgId: string) {
    const by = new Map<string, Playbook>();
    for (const p of await this.db.playbooks.list(orgId)) if (!by.has(p.key) || by.get(p.key)!.version < p.version) by.set(p.key, p);
    return [...by.values()];
  }
  async list(orgId: string) {
    const a = await this.automation(orgId);
    return Promise.all((await this.latest(orgId)).map(async (p) => ({ ...p, enabled: ((await this.setting(orgId, `playbook-state:${p.key}`)) as { enabled?: boolean } | undefined)?.enabled ?? p.enabled, effectiveMode: this.effectiveMode(p, a) })));
  }
  versions(orgId: string, key: string) { return this.db.playbooks.where(orgId, { key }); }
  async setEnabled(me: Principal, key: string, enabled: boolean) {
    if (!(await this.db.playbooks.where(me.orgId, { key })).length) throw new NotFoundException('playbook not found');
    await this.setSetting(me.orgId, `playbook-state:${key}`, { enabled }, me.userId);
    await this.audit.append(me.orgId, me.userId, enabled ? 'playbook.enabled' : 'playbook.disabled', { key });
    return { key, enabled };
  }
  async installDefaults(me: Principal) {
    const owner = me.email || me.userId, out: string[] = [];
    const defs: Array<z.input<typeof PlaybookSchema>> = [
      { key: 'exposed-credential', name: 'Exposed credential detected', description: 'A scanner found a live secret: open a ticket, alert, and prepare a rotation request.', owner, riskLevel: 'medium', mode: 'ASSISTED', trigger: { type: 'finding' }, conditions: [{ field: 'kind', op: 'eq', value: 'secret' }],
        actions: [{ type: 'create_ticket', params: { title: 'Rotate exposed credential: {{trigger.title}}', body: 'Location: {{trigger.location}} (masked: {{trigger.maskedSecret}})', severity: 'high' } }, { type: 'notify', params: { subject: 'Exposed credential: {{trigger.title}}' } }, { type: 'propose_config_fix', params: { fix: 'rotate_credential', credentialId: '{{trigger.credentialId}}', target: '{{trigger.assetName}}' } }] },
      { key: 'endpoint-compromised', name: 'Endpoint likely compromised', description: 'EDR/SIEM reports a high-severity detection: open a case, alert and propose isolating the endpoint.', owner, riskLevel: 'high', mode: 'ASSISTED', trigger: { type: 'signal' },
        conditions: [{ field: 'severity', op: 'gte', value: 'high' }, { field: 'source', op: 'in', value: ['crowdstrike', 'defender', 'wazuh'] }, { field: 'host', op: 'exists' }],
        actions: [{ type: 'create_case', params: { name: 'Possible endpoint compromise: {{trigger.host}}' } }, { type: 'notify', params: { subject: 'High-severity detection on {{trigger.host}}: {{trigger.title}}' } }, { type: 'propose_endpoint_isolation', params: { target: '{{trigger.host}}', reason: '{{trigger.title}}' } }] },
      { key: 'critical-vulnerability', name: 'Immediate-priority vulnerability', description: 'A vulnerability reached priority "immediate": ticket, alert and a patch request.', owner, riskLevel: 'medium', mode: 'ASSISTED', trigger: { type: 'vulnerability' }, conditions: [{ field: 'priority.level', op: 'eq', value: 'immediate' }],
        actions: [{ type: 'create_ticket', params: { title: 'Patch {{trigger.cve}} on {{trigger.assetName}}', body: '{{trigger.priority.explanation}}', severity: 'critical' } }, { type: 'notify', params: { subject: 'Immediate-priority vulnerability {{trigger.cve}} on {{trigger.assetName}}' } }, { type: 'propose_patch_request', params: { target: '{{trigger.assetName}}', cve: '{{trigger.cve}}' } }] },
      { key: 'suspicious-access', name: 'Suspicious access / brute force', description: 'Authentication abuse is detected: alert and propose revoking sessions of the identity.', owner, riskLevel: 'medium', mode: 'ASSISTED', trigger: { type: 'signal' },
        conditions: [{ field: 'severity', op: 'gte', value: 'medium' }, { field: 'title', op: 'contains', value: 'brute force' }, { field: 'user', op: 'exists' }],
        actions: [{ type: 'notify', params: { subject: 'Suspicious access for {{trigger.user}}: {{trigger.title}}' } }, { type: 'propose_session_revoke', params: { identity: '{{trigger.user}}' } }] },
      { key: 'exposed-asset', name: 'Confirmed high-risk exposure', description: 'An exposure was confirmed on an asset: ticket and a configuration fix proposal.', owner, riskLevel: 'medium', mode: 'ASSISTED', trigger: { type: 'exposure' }, conditions: [{ field: 'confidence', op: 'eq', value: 'confirmed' }, { field: 'severity', op: 'gte', value: 'high' }],
        actions: [{ type: 'create_ticket', params: { title: 'Exposure: {{trigger.title}} on {{trigger.assetName}}', body: '{{trigger.detail}}', severity: 'high' } }, { type: 'propose_config_fix', params: { target: '{{trigger.assetName}}', fix: '{{trigger.title}}' } }] },
      { key: 'excessive-privileges', name: 'Excessive privileges', description: 'An identity uses a fraction of its permissions: propose a least-privilege reduction.', owner, riskLevel: 'high', mode: 'ASSISTED', trigger: { type: 'identity' }, conditions: [{ field: 'riskCodes', op: 'contains', value: 'excessive_permissions' }],
        actions: [{ type: 'notify', params: { subject: 'Excessive permissions: {{trigger.name}}' } }, { type: 'propose_permission_change', params: { identity: '{{trigger.name}}', identityId: '{{trigger.id}}' } }] },
    ];
    for (const d of defs) { if ((await this.db.playbooks.where(me.orgId, { key: d.key })).length) continue; await this.publish(me, PlaybookSchema.parse(d)); out.push(d.key); }
    return { installed: out };
  }

  // ───────── triggering ─────────
  private async handle(e: DomainEvent) {
    const a = await this.automation(e.orgId);
    for (const pb of await this.latest(e.orgId)) {
      if (pb.trigger.type !== e.type) continue;
      if (!(((await this.setting(e.orgId, `playbook-state:${pb.key}`)) as { enabled?: boolean } | undefined)?.enabled ?? pb.enabled)) continue;
      if (pb.trigger.kind && get(e.entity, 'kind') !== pb.trigger.kind) continue;
      if (!pb.conditions.every((c) => evalCondition(c, e.entity))) continue;
      await this.start(e.orgId, pb, a, e.type, String(e.entity['id'] ?? sha256(JSON.stringify(e.entity))), e.entity, ('actor' in e ? (e as { actor?: string }).actor : undefined) ?? 'system');
    }
  }
  /** Manual evaluation against an existing entity (tests, dry reruns, "run this playbook now"). */
  async trigger(me: Principal, type: TriggerType, entityId: string) {
    const repoOf = { signal: this.db.signals, finding: this.db.findings, vulnerability: this.db.vulns, exposure: this.db.exposures } as const;
    let entity: Record<string, any> | undefined;
    if (type === 'identity') { const i = await this.db.identities.get(me.orgId, entityId); if (i) entity = { ...i, riskCodes: (await this.iam.risks(me.orgId)).filter((r) => r.identityId === i.id).map((r) => r.code) }; }
    else entity = (await repoOf[type].get(me.orgId, entityId)) as Record<string, any> | undefined;
    if (!entity) throw new NotFoundException(`${type} not found`);
    if (entity['assetId'] && !entity['assetName']) entity['assetName'] = (await this.db.inventory.get(me.orgId, entity['assetId']))?.name;
    const before = (await this.db.runs.list(me.orgId)).length;
    await this.bus.emit({ type, orgId: me.orgId, entity, actor: me.userId } as DomainEvent);
    return { runs: (await this.db.runs.list(me.orgId)).length - before };
  }
  /** Evaluates identity risks and raises one identity event per (identity) with its risk codes; playbooks then decide. Safe to call repeatedly: runs are unique per playbook+identity. */
  async scanIdentities(me: Pick<Principal, 'orgId' | 'userId'>) {
    const risks = await this.iam.risks(me.orgId), by = new Map<string, string[]>();
    for (const r of risks) if (r.confidence !== 'unverified') by.set(r.identityId, [...(by.get(r.identityId) ?? []), r.code]);
    let n = 0;
    for (const [id, codes] of by) { const i = await this.db.identities.get(me.orgId, id); if (!i) continue; await this.bus.emit({ type: 'identity', orgId: me.orgId, entity: { ...i, riskCodes: codes }, actor: me.userId } as DomainEvent); n++; }
    return { evaluated: n };
  }

  private async start(orgId: string, pb: Playbook, a: AutomationSettings, type: TriggerType, refId: string, entity: Record<string, any>, requestedBy: string) {
    const groupKey = typeof entity['host'] === 'string' && entity['host'] ? `host:${entity['host']}` : undefined;
    if (groupKey) {
      const open = (await this.db.runs.where(orgId, { playbookKey: pb.key, groupKey, status: 'awaiting_approval' }))[0];
      if (open) { await this.db.runs.update(orgId, open.id, (r) => { if (!r.evidence.includes(`${type}:${refId}`)) r.evidence.push(`${type}:${refId}`); r.history.push({ at: now(), text: `further ${type} ${refId} for ${groupKey} attached to this run (no duplicate approval opened)` }); r.updatedAt = now(); }); return open; }
    }
    const mode = this.effectiveMode(pb, a), ctx = { trigger: entity }, runId = newId('run');
    const steps: RunStep[] = pb.actions.map((x, index) => {
      const params = render(x.params, ctx) as Record<string, unknown>, idempotencyKey = `${runId}:${index}`;
      return { index, action: x.type, params, risky: !SAFE_ACTIONS.has(x.type), status: 'planned', idempotencyKey, planHash: sha256(stableStringify({ runId, index, action: x.type, params })) };
    });
    const t = now();
    const run: PlaybookRun = { id: runId, orgId, playbookId: pb.id, playbookKey: pb.key, playbookVersion: pb.version, mode: pb.mode, effectiveMode: mode, trigger: { type, refId }, dedupKey: `${pb.key}:${type}:${refId}`, groupKey, requestedBy, evidence: [`${type}:${refId}`],
      steps, status: 'executing', createdAt: t, updatedAt: t, history: [{ at: t, text: `triggered by ${type} ${refId}; mode ${mode}${mode !== pb.mode ? ` (playbook asks for ${pb.mode}${a.killSwitch ? ', kill switch engaged' : ''})` : ''}` }] };
    const { row, created } = await this.db.runs.createUnique(run, { dedupKey: run.dedupKey });
    if (!created) return row;                                               // idempotent: the same entity never fires the same playbook twice
    this.metrics.inc('sentinel_playbook_runs_total', { mode }, 1, 'playbook runs by effective mode');
    await this.audit.append(orgId, requestedBy, 'playbook.run_started', { runId, playbook: pb.key, version: pb.version, mode, trigger: { type, refId } });
    await this.advance(orgId, runId, pb, entity);
    return row;
  }

  // ───────── execution ─────────
  private async canAutoExecute(orgId: string, pb: Playbook, step: RunStep, a: AutomationSettings) {
    if (a.killSwitch || !a.automatedEnabled || pb.riskLevel === 'high' || !a.allowedAutoActions.includes(step.action)) return false;
    const hourAgo = new Date(Date.now() - 3600_000).toISOString();
    const autos = (await this.db.runs.list(orgId, (r) => r.updatedAt >= hourAgo)).reduce((n, r) => n + r.steps.filter((s) => s.risky && s.result?.['auto'] === true).length, 0);
    return autos < a.maxActionsPerHour;
  }
  private async advance(orgId: string, runId: string, pb: Playbook, entity: Record<string, any>) {
    const a = await this.automation(orgId);
    for (;;) {
      const run = (await this.db.runs.get(orgId, runId))!;
      if (run.status === 'stopped') return;
      const step = run.steps.find((s) => s.status === 'planned' || s.status === 'approved');
      const mode = this.effectiveMode(pb, a);
      if (!step) { await this.finish(orgId, runId, run.steps.some((s) => s.status === 'failed') ? 'failed' : mode === 'OBSERVE' ? 'observed' : 'completed'); return; }
      const observeOk = step.action === 'notify' || step.action === 'create_case';
      if (mode === 'OBSERVE' && !observeOk) { await this.setStep(orgId, runId, step.index, { status: 'skipped', result: { reason: `OBSERVE mode: "${step.action}" would run here; nothing is executed` } }, `OBSERVE: skipped ${step.action}`); continue; }
      if (step.risky && step.status !== 'approved') {
        if (!(mode === 'AUTOMATED' && (await this.canAutoExecute(orgId, pb, step, a)))) {
          const ap = await this.approvals.request(orgId, runId, `step-${step.index}`, { id: `${runId}:${step.index}`, planHash: step.planHash! });
          await this.setStep(orgId, runId, step.index, { status: 'awaiting_approval', approvalId: ap.id }, `${step.action} proposed; waiting for human approval (${ap.id})`);
          await this.db.runs.update(orgId, runId, { status: 'awaiting_approval' });
          await this.notify.dispatch(orgId, { event: 'soar.approval_requested', severity: pb.riskLevel === 'high' ? 'high' : 'medium', subject: `Approval needed: ${step.action} (${pb.name})`, body: `Playbook ${pb.key} v${pb.version} proposes ${step.action} on ${String(step.params['target'] ?? step.params['identity'] ?? run.trigger.refId)}. Nothing runs until an approver signs.`, dedupKey: this.notify.dedup(['appr', ap.id]) }).catch(() => undefined);
          return;
        }
      }
      try {
        const auto = step.risky && step.status !== 'approved';
        const result = await this.runStep(orgId, run, step, entity);
        await this.setStep(orgId, runId, step.index, { status: 'executed', result: { ...result, ...(auto ? { auto: true } : {}) } }, `${step.action} executed${auto ? ' automatically (policy allows it)' : ''}`);
        await this.audit.append(orgId, 'system', 'playbook.step_executed', { runId, step: step.index, action: step.action, auto, result });
        const caseId = (run.steps.find((s) => s.action === 'create_case' && s.result)?.result?.['caseId'] as string | undefined) ?? (result['caseId'] as string | undefined);
        if (caseId && step.risky) await this.cases.recordAction('playbook', orgId, caseId, `${step.action} (${pb.key})`, JSON.stringify(result));
      } catch (e) {
        await this.setStep(orgId, runId, step.index, { status: 'failed', result: { error: redactString((e as Error).message).slice(0, 300) } }, `${step.action} FAILED`);
        await this.audit.append(orgId, 'system', 'playbook.step_failed', { runId, step: step.index, action: step.action, error: (e as Error).message });
        await this.finish(orgId, runId, 'failed'); return;
      }
    }
  }
  private async runStep(orgId: string, run: PlaybookRun, step: RunStep, entity: Record<string, any>): Promise<Record<string, unknown>> {
    const p = step.params;
    switch (step.action) {
      case 'notify': {
        const sev = (typeof p['severity'] === 'string' && p['severity'] in SEV_RANK ? p['severity'] : (entity['severity'] in SEV_RANK ? entity['severity'] : 'medium')) as Severity;
        const logs = await this.notify.dispatch(orgId, { event: `playbook.${run.playbookKey}`, severity: sev, subject: String(p['subject'] ?? `Playbook ${run.playbookKey}`), body: String(p['body'] ?? `Triggered by ${run.trigger.type} ${run.trigger.refId}`), dedupKey: this.notify.dedup([run.playbookKey, run.trigger.refId]) });
        return { channels: logs.length, delivered: logs.filter((l) => l.status === 'delivered').length, failed: logs.filter((l) => l.status === 'failed').length, suppressed: logs.filter((l) => l.status === 'suppressed').length, ...(logs.length ? {} : { note: 'no notification channel matched' }) };
      }
      case 'create_case': {
        const asset = entity['assetId'] ?? (entity['type'] ? entity['id'] : undefined);
        const c = await this.cases.open({ orgId, userId: 'playbook' }, { name: String(p['name'] ?? `Case from ${run.playbookKey}`).slice(0, 200), description: `Opened by playbook ${run.playbookKey} v${run.playbookVersion} for ${run.trigger.type} ${run.trigger.refId}.`, severity: (['critical', 'high', 'medium', 'low', 'info'].includes(String(entity['severity'])) ? entity['severity'] : 'medium') as Severity,
          assetIds: asset && (await this.db.inventory.get(orgId, asset)) ? [asset] : [], identityIds: entity['identityId'] && (await this.db.identities.get(orgId, entity['identityId'])) ? [entity['identityId']] : [], vulnerabilityIds: [], signalIds: run.trigger.type === 'signal' ? [run.trigger.refId] : [], recommendations: [] }, 'playbook');
        return { caseId: c.id, number: c.number };
      }
      case 'create_ticket': {
        const t = { id: newId('tkt'), orgId, title: String(p['title'] ?? `Ticket from ${run.playbookKey}`).slice(0, 200), body: String(p['body'] ?? '').slice(0, 4000), severity: (['critical', 'high', 'medium', 'low', 'info'].includes(String(p['severity'])) ? p['severity'] : 'medium') as Severity, status: 'open' as const, createdAt: now(), source: `playbook:${run.playbookKey}` };
        await this.db.tickets.put(t); return { ticketId: t.id };
      }
      case 'tag': {
        const id = String(entity['assetId'] ?? p['assetId'] ?? ''), tag = String(p['tag'] ?? ''); const a = id ? await this.db.inventory.get(orgId, id) : undefined;
        if (!a || !tag) return { note: 'no asset to tag' }; await this.db.inventory.update(orgId, id, (r) => { r.tags = [...new Set([...r.tags, tag])].slice(0, 30); }); return { tagged: id, tag };
      }
      default: {
        const a = await this.automation(orgId); if (a.killSwitch) throw new ConflictException('kill switch is engaged');
        return this.executor.execute(orgId, run, step);
      }
    }
  }
  private setStep(orgId: string, runId: string, index: number, patch: Partial<RunStep>, text: string) {
    return this.db.runs.update(orgId, runId, (r) => { Object.assign(r.steps[index], patch); r.updatedAt = now(); r.history.push({ at: now(), text }); });
  }
  private async finish(orgId: string, runId: string, status: PlaybookRun['status'], reason?: string) {
    await this.db.runs.update(orgId, runId, (r) => { r.status = status; r.reason = reason; r.updatedAt = now(); r.history.push({ at: now(), text: `run ${status}${reason ? `: ${reason}` : ''}` }); });
    await this.audit.append(orgId, 'system', `playbook.run_${status}`, { runId, reason });
  }

  /** A human decided on a proposed step. Executes only if the signature verifies AND is bound to this exact step payload. */
  private async afterDecision(orgId: string, runId: string, stepName: string, approved: boolean) {
    const run = await this.db.runs.get(orgId, runId); if (!run || run.status === 'stopped') return;
    const index = Number(stepName.slice(5)), step = run.steps[index]; if (!step || step.status !== 'awaiting_approval') return;
    const pb = await this.db.playbooks.get(orgId, run.playbookId); if (!pb) return;
    if (!approved) {
      await this.db.runs.update(orgId, runId, (r) => { r.steps[index].status = 'rejected'; for (const s of r.steps) if (s.index > index && (s.status === 'planned' || s.status === 'awaiting_approval')) s.status = 'skipped'; r.updatedAt = now(); r.history.push({ at: now(), text: `step ${index} (${step.action}) rejected by a human; remaining steps skipped` }); });
      await this.finish(orgId, runId, 'rejected', 'rejected by an approver'); return;
    }
    const a = await this.approvals.find(orgId, runId, stepName);
    const expected = sha256(stableStringify({ runId, index, action: step.action, params: step.params }));
    if (!a || !(await this.signer.verifyApproval(a)) || a.planHash !== step.planHash || step.planHash !== expected) {
      await this.setStep(orgId, runId, index, { status: 'failed', result: { error: 'approval signature invalid or not bound to this exact action' } }, 'approval did not verify; step NOT executed');
      await this.finish(orgId, runId, 'failed', 'approval did not verify'); return;
    }
    if ((await this.automation(orgId)).killSwitch) { await this.setStep(orgId, runId, index, { status: 'skipped', result: { reason: 'kill switch engaged' } }, 'kill switch engaged: approved step not executed'); await this.finish(orgId, runId, 'stopped', 'kill switch'); return; }
    await this.setStep(orgId, runId, index, { status: 'approved' }, `approved by ${a.decidedBy}`);
    await this.db.runs.update(orgId, runId, { status: 'executing' });
    const entity = { ...(await this.entityOf(orgId, run)) };
    await this.advance(orgId, runId, pb, entity);
  }
  private async entityOf(orgId: string, run: PlaybookRun): Promise<Record<string, any>> {
    const repo = { signal: this.db.signals, finding: this.db.findings, vulnerability: this.db.vulns, exposure: this.db.exposures, identity: this.db.identities }[run.trigger.type] as { get(o: string, id: string): Promise<Record<string, any> | undefined> };
    return (await repo.get(orgId, run.trigger.refId)) ?? { id: run.trigger.refId };
  }

  // ───────── runs ─────────
  async runs(orgId: string, q: { status?: string; playbook?: string }) { return (await this.db.runs.list(orgId, (r) => (!q.status || q.status.split(',').includes(r.status)) && (!q.playbook || r.playbookKey === q.playbook))).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 300); }
  async run(orgId: string, id: string) { const r = await this.db.runs.get(orgId, id); if (!r) throw new NotFoundException('run not found'); return { run: r, effects: await this.db.labEffects.where(orgId, { runId: id }) }; }
  async stop(me: Pick<Principal, 'orgId' | 'userId'>, id: string, reason = 'stopped by operator') {
    const r = await this.db.runs.get(me.orgId, id); if (!r) throw new NotFoundException('run not found');
    if (['completed', 'failed', 'rejected', 'stopped'].includes(r.status)) throw new ConflictException(`run already ${r.status}`);
    await this.db.runs.update(me.orgId, id, (x) => { x.status = 'stopped'; x.reason = reason; for (const s of x.steps) if (s.status === 'planned' || s.status === 'awaiting_approval' || s.status === 'approved') s.status = 'skipped'; x.updatedAt = now(); x.history.push({ at: now(), text: `stopped: ${reason}` }); });
    await this.audit.append(me.orgId, me.userId, 'playbook.run_stopped', { runId: id, reason });
    return { id, status: 'stopped' };
  }
  /** Pending human decisions with the exact step payload the approver is signing. */
  async pendingApprovals(orgId: string) {
    const out = [];
    for (const ap of (await this.approvals.list(orgId, 'pending')).filter((x) => x.stepName.startsWith('step-'))) {
      const run = await this.db.runs.get(orgId, ap.executionId); if (!run) continue;
      const step = run.steps[Number(ap.stepName.slice(5))];
      out.push({ approvalId: ap.id, runId: run.id, playbook: run.playbookKey, version: run.playbookVersion, trigger: run.trigger, requestedBy: run.requestedBy, requestedAt: ap.requestedAt, action: step?.action, params: step?.params, planHash: ap.planHash, riskLevel: (await this.db.playbooks.get(orgId, run.playbookId))?.riskLevel, effectiveMode: run.effectiveMode });
    }
    return out;
  }
}
