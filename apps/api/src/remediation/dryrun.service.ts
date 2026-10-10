import { Injectable } from '@nestjs/common';
import { Db } from '../store/db';
import { DryRunPlan, PolicyDoc } from '../store/models';
import { newId, now, sha256, stableStringify } from '../common/ids';
import { redact } from '../common/mask';

export type PlanKind = DryRunPlan['kind'];
export interface SimulateInput { kind: Exclude<PlanKind, 'terraform'>; targetRef: string; params: Record<string, unknown>; sourceFindingId?: string }

const ACTION_BY_KIND = { waf: 'apply_waf_rule', iam: 'apply_iam_policy', isolation: 'isolate_service', rotation: 'revoke_credential' } as const;

/**
 * Pure planning: builds a diff + Terraform preview. It has NO dependency on any InfraAdapter,
 * so generating a plan cannot have side effects by construction.
 */
@Injectable()
export class DryRunService {
  constructor(private db: Db) {}

  static planHash(p: Pick<DryRunPlan, 'kind' | 'targetRef' | 'action' | 'params' | 'diff'>) {
    return sha256(stableStringify({ kind: p.kind, targetRef: p.targetRef, action: p.action, params: p.params, diff: p.diff }));
  }

  simulate(orgId: string, i: SimulateInput): DryRunPlan {
    const params = redact(i.params);
    let diff: string, terraform: string, destructive = true;
    switch (i.kind) {
      case 'waf': ({ diff, terraform } = this.waf(i.targetRef, params)); break;
      case 'iam': ({ diff, terraform } = this.iam(i.targetRef, params)); break;
      case 'isolation': ({ diff, terraform } = this.isolation(i.targetRef)); break;
      case 'rotation': ({ diff, terraform } = this.rotation(i.targetRef, params)); break;
    }
    const base = { kind: i.kind, targetRef: i.targetRef, action: ACTION_BY_KIND[i.kind], params, diff };
    const plan: DryRunPlan = { id: newId('plan'), orgId, ...base, terraform, planHash: DryRunService.planHash(base), destructive, applied: false, sourceFindingId: i.sourceFindingId, createdAt: now() };
    return this.db.plans.put(plan);
  }

  /** Detects tampering of a stored plan between approval and execution. */
  intact(plan: DryRunPlan) { return DryRunService.planHash(plan) === plan.planHash; }

  private waf(target: string, p: Record<string, unknown>) {
    const rule = (p['rule'] ?? {}) as { name?: string; action?: string; match?: string; priority?: number; addresses?: string[] };
    const name = rule.name ?? 'block-suspicious'; const action = (rule.action ?? 'block').toLowerCase();
    return {
      diff: [`--- waf/${target} (current)`, `+++ waf/${target} (proposed)`, `+ rule "${name}" priority=${rule.priority ?? 100}`, `+   match:  ip_set ${name}-ips [${(rule.addresses ?? []).join(', ') || 'none'}]`, `+   action: ${action.toUpperCase()}`].join('\n'),
      terraform: `resource "aws_wafv2_ip_set" "${name.replace(/\W/g, '_')}_ips" {\n  name               = "${name}-ips"\n  scope              = "REGIONAL"\n  ip_address_version = "IPV4"\n  addresses          = ${JSON.stringify(rule.addresses ?? [])}\n}\n\nresource "aws_wafv2_rule_group" "${name.replace(/\W/g, '_')}" {\n  name     = "${name}"\n  scope    = "REGIONAL"\n  capacity = 10\n  rule {\n    name     = "${name}"\n    priority = ${rule.priority ?? 100}\n    action { ${action} {} }\n    statement { ip_set_reference_statement { arn = aws_wafv2_ip_set.${name.replace(/\W/g, '_')}_ips.arn } }\n    visibility_config {\n      cloudwatch_metrics_enabled = true\n      metric_name                = "${name}"\n      sampled_requests_enabled   = true\n    }\n  }\n  visibility_config {\n    cloudwatch_metrics_enabled = true\n    metric_name                = "${name}-group"\n    sampled_requests_enabled   = true\n  }\n}`,
    };
  }

  private iam(role: string, p: Record<string, unknown>) {
    const cur = (p['current'] as PolicyDoc | undefined)?.statements.flatMap((s) => s.actions) ?? [];
    const next = (p['proposed'] as PolicyDoc | undefined)?.statements.flatMap((s) => s.actions) ?? [];
    const removed = cur.filter((a) => !next.includes(a)); const kept = next;
    return {
      diff: [`--- iam/${role} (current)`, `+++ iam/${role} (proposed)`, ...kept.map((a) => `  ${a}`), ...removed.map((a) => `- ${a}`)].join('\n'),
      terraform: `resource "aws_iam_role_policy" "${role.replace(/\W/g, '_')}_least_privilege" {\n  role   = "${role}"\n  policy = jsonencode(${JSON.stringify(p['proposed'] ?? {}, null, 2).replace(/\n/g, '\n  ')})\n}`,
    };
  }

  private isolation(target: string) {
    return {
      diff: [`--- network/${target} (current)`, `+++ network/${target} (proposed)`, `- egress 0.0.0.0/0`, `- ingress 0.0.0.0/0:443`, `+ ingress forensic-bastion:22 (only)`].join('\n'),
      terraform: `resource "aws_security_group" "${target.replace(/\W/g, '_')}_quarantine" {\n  name        = "${target}-quarantine"\n  description = "SentinelMesh quarantine (revokes all other rules)"\n  # no egress rules → deny all\n  ingress { from_port = 22 to_port = 22 protocol = "tcp" security_groups = [aws_security_group.forensic_bastion.id] }\n}`,
    };
  }

  private rotation(cred: string, p: Record<string, unknown>) {
    return {
      diff: [`--- credential/${cred}`, `+++ credential/${cred}`, `  new version created, secret store repointed, health-checked (done before approval)`, `- revoke the previous credential version (REQUIRES APPROVAL)`].join('\n'),
      terraform: `# No Terraform change: rotation is performed through the secret provider API.`,
    };
  }
}
