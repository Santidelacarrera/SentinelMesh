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
  publish(orgId: string, key: string, steps: StepDef[], actor = 'system'): SecurityWorkflow {
    for (const s of steps) {
      if (DESTRUCTIVE_ACTIONS.has(s.action) && !s.destructive) throw new BadRequestException(`step "${s.name}" uses destructive action ${s.action} and must be marked destructive (approval-gated)`);
    }
    if (new Set(steps.map((s) => s.name)).size !== steps.length) throw new BadRequestException('duplicate step names');
    const prev = this.latest(orgId, key);
    const frozen = Object.freeze(steps.map((s) => Object.freeze({ ...s })));
    const wf: SecurityWorkflow = { id: newId('wf'), orgId, key, version: (prev?.version ?? 0) + 1, steps: frozen as StepDef[], contentHash: sha256(stableStringify(steps)), createdAt: now() };
    this.db.workflows.put(wf);
    this.audit.append(orgId, actor, 'workflow.published', { key, version: wf.version, contentHash: wf.contentHash });
    return wf;
  }

  latest(orgId: string, key: string) {
    return this.db.workflows.list(orgId, (w) => w.key === key).sort((a, b) => b.version - a.version)[0];
  }

  resolve(orgId: string, key: string): SecurityWorkflow {
    const wf = this.latest(orgId, key) ?? (DEFAULT_WORKFLOWS[key] ? this.publish(orgId, key, DEFAULT_WORKFLOWS[key]) : undefined);
    if (!wf) throw new NotFoundException(`unknown workflow ${key}`);
    return wf;
  }
}
