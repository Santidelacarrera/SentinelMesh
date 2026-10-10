import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { DryRunService } from './dryrun.service';
import { WorkflowEngine } from '../workflow/engine';
import { AnalyticsClient } from '../analytics/analytics.client';
import { AuditTrail } from '../audit/audit-trail';
import { newId, now } from '../common/ids';
import { Principal } from '../auth/auth';
import { PolicyDoc } from '../store/models';

export const SimulateSchema = z.object({
  findingId: z.string().optional(),
  kind: z.enum(['waf', 'iam', 'isolation']),
  targetRef: z.string().min(1).max(200),
  params: z.record(z.string(), z.unknown()).default({}),
  submitForApproval: z.boolean().default(false),
}).strict();

export const IamAuditSchema = z.object({
  roleName: z.string().min(1).max(128), critical: z.boolean().default(false),
  grantedActions: z.array(z.string().min(1).max(128)).min(1).max(2000),
  auditEvents: z.array(z.string().min(1).max(128)).max(100000),
  resources: z.array(z.string().max(512)).default(['*']),
  submitForApproval: z.boolean().default(false),
}).strict();

export const RotateSchema = z.object({ credentialId: z.string().min(1), findingId: z.string().optional() }).strict();

const WORKFLOW_BY_KIND = { waf: 'waf-remediation', iam: 'iam-trim', isolation: 'incident-response' } as const;
const STEP_BY_KIND = { waf: 'apply-waf-rule', iam: 'apply-iam-policy', isolation: 'isolate-service' } as const;

@Injectable()
export class RemediationService {
  constructor(private db: Db, private dryrun: DryRunService, private engine: WorkflowEngine, private analytics: AnalyticsClient, private audit: AuditTrail) {}

  /** Generates a dry-run plan. With submitForApproval it also opens an execution that PAUSES at the approval gate. */
  async simulate(me: Principal, input: z.infer<typeof SimulateSchema>) {
    if (input.findingId && !this.db.findings.get(me.orgId, input.findingId)) throw new NotFoundException('finding not found');
    if (input.kind === 'isolation' && input.submitForApproval) throw new BadRequestException('isolation is submitted through incident triage');
    const plan = this.dryrun.simulate(me.orgId, { kind: input.kind, targetRef: input.targetRef, params: input.params, sourceFindingId: input.findingId });
    if (input.findingId) this.db.findings.update(me.orgId, input.findingId, (f) => { f.remediationPlanIds.push(plan.id); });
    this.audit.append(me.orgId, me.userId, 'plan.simulated', { planId: plan.id, kind: plan.kind, planHash: plan.planHash, target: plan.targetRef });
    let executionId: string | undefined;
    if (input.submitForApproval) {
      const ex = await this.engine.start(me.orgId, WORKFLOW_BY_KIND[input.kind], { plans: { [STEP_BY_KIND[input.kind]]: plan.id } }, me.userId);
      executionId = ex.id;
      if (input.findingId) this.db.findings.update(me.orgId, input.findingId, { status: 'remediating' });
    }
    return { plan, executionId, applied: false };
  }

  async auditRole(me: Principal, input: z.infer<typeof IamAuditSchema>) {
    const r = await this.analytics.leastPrivilege(input.grantedActions, input.auditEvents, input.resources);
    const audit = this.db.identityAudits.put({ id: newId('iam'), orgId: me.orgId, roleName: input.roleName, critical: input.critical, granted: r.granted, used: r.used, unused: r.unused, usageRatio: r.usageRatio, proposedPolicy: r.proposedPolicy, createdAt: now() });
    this.audit.append(me.orgId, me.userId, 'iam.audited', { roleName: input.roleName, usageRatio: r.usageRatio, unused: r.unused.length });
    let plan, executionId;
    if (input.submitForApproval && r.unused.length) {
      const current: PolicyDoc = { version: '2012-10-17', statements: [{ effect: 'Allow', actions: r.granted, resources: input.resources }] };
      const s = await this.simulate(me, { kind: 'iam', targetRef: input.roleName, params: { roleName: input.roleName, current, proposed: r.proposedPolicy, critical: input.critical }, submitForApproval: true });
      plan = s.plan; executionId = s.executionId;
    }
    return { audit, plan, executionId };
  }

  /** Starts rotation. Steps 1-3 run automatically (non-destructive, health-checked); revoking the old credential waits for approval. */
  async rotate(me: Principal, input: z.infer<typeof RotateSchema>) {
    const cred = this.db.credentials.get(me.orgId, input.credentialId);
    if (!cred) throw new NotFoundException('credential not found');
    const plan = this.dryrun.simulate(me.orgId, { kind: 'rotation', targetRef: cred.id, params: { credentialId: cred.id, service: cred.service, masterSecret: cred.kind === 'master_secret' }, sourceFindingId: input.findingId });
    if (input.findingId) this.db.findings.update(me.orgId, input.findingId, (f) => { f.remediationPlanIds.push(plan.id); f.status = 'remediating'; });
    const ex = await this.engine.start(me.orgId, 'credential-rotation', { credentialId: cred.id, plans: { 'revoke-old-credential': plan.id } }, me.userId);
    return { executionId: ex.id, plan };
  }
}
