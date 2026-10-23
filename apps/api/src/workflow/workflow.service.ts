import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { Db } from '../store/db';
import { SecurityWorkflow, StepDef, ActionType } from '../store/models';
import { newId, now, sha256, stableStringify } from '../common/ids';
import { AuditTrail } from '../audit/audit-trail';

/** Actions that change the outside world destructively. A step using one MUST be declared destructive. */
export const DESTRUCTIVE_ACTIONS: ReadonlySet<ActionType> = new Set(['revoke_credential', 'apply_waf_rule', 'apply_iam_policy', 'isolate_service']);

export const DEFAULT_WORKFLOWS: Record<string, StepDef[]> = {
  'credential-rotation': [
    { name: 'create-new-credential', action: 'create_credential' },
    { name: 'update-secret-store', action: 'update_secret_store' },
    { name: 'healthcheck-new-credential', action: 'healthcheck' },
    { name: 'revoke-old-credential', action: 'revoke_credential', destructive: true },
  ],
  'waf-remediation': [{ name: 'apply-waf-rule', action: 'apply_waf_rule', destructive: true }],
  'iam-trim': [{ name: 'apply-iam-policy', action: 'apply_iam_policy', destructive: true }],
  'incident-response': [
    { name: 'collect-forensics', action: 'collect_forensics' },
    { name: 'summarize-evidence', action: 'summarize' },
    { name: 'isolate-service', action: 'isolate_service', destructive: true },
    { name: 'notify-secops', action: 'notify' },
  ],
};

@Injectable()
export class WorkflowService {
  constructor(private db: Db, private audit: AuditTrail) {}

  /** Publishing creates a NEW immutable version; there is intentionally no update/delete. */
  async publish(orgId: string, key: string, steps: StepDef[], actor = 'system'): Promise<SecurityWorkflow> {
    for (const s of steps) {
      if (DESTRUCTIVE_ACTIONS.has(s.action) && !s.destructive) throw new BadRequestException(`step "${s.name}" uses destructive action ${s.action} and must be marked destructive (approval-gated)`);
    }
    if (new Set(steps.map((s) => s.name)).size !== steps.length) throw new BadRequestException('duplicate step names');
    const frozen = steps.map((s) => ({ ...s }));
    // Optimistic versioning: if another replica published the same version first, the unique (key, version) loses the race → retry with the next one.
    for (let attempt = 0; attempt < 5; attempt++) {
      const prev = await this.latest(orgId, key);
      const wf: SecurityWorkflow = { id: newId('wf'), orgId, key, version: (prev?.version ?? 0) + 1, steps: frozen, contentHash: sha256(stableStringify(steps)), createdAt: now() };
      const { row, created } = await this.db.workflows.createUnique(wf, { key, version: wf.version });
      if (!created) continue;
      await this.audit.append(orgId, actor, 'workflow.published', { key, version: row.version, contentHash: row.contentHash });
      return row;
    }
    throw new BadRequestException('could not publish workflow: too much contention');
  }

  async latest(orgId: string, key: string) {
    return (await this.db.workflows.where(orgId, { key })).sort((a, b) => b.version - a.version)[0];
  }

  async resolve(orgId: string, key: string): Promise<SecurityWorkflow> {
    const wf = (await this.latest(orgId, key)) ?? (DEFAULT_WORKFLOWS[key] ? await this.publish(orgId, key, DEFAULT_WORKFLOWS[key]) : undefined);
    if (!wf) throw new NotFoundException(`unknown workflow ${key}`);
    return wf;
  }
}
