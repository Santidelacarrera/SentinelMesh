import { createHash } from 'node:crypto';

/** HCL string literal: JSON escaping plus neutralised `${` / `%{` so user-supplied text can never become a template expression. */
const neutralise = (s: string) => s.replace(/\$\{/g, () => '$${').replace(/%\{/g, () => '%%{');   // function replacers: '$$' in a string replacement means a single '$'
export const hclStr = (s: string) => neutralise(JSON.stringify(s));
const heredoc = (tag: string, body: string) => `<<-${tag}\n${neutralise(body)}\n${tag}`;

export interface WafRuleSpec { name: string; action?: string; priority?: number; addresses: string[]; scope?: 'REGIONAL' | 'CLOUDFRONT' }
export interface IamSpec { roleName: string; proposed: { version: string; statements: Array<{ effect: string; actions: string[]; resources: string[] }> }; replacePolicyName?: string }
export type HclFiles = Record<string, string>;

// bounded quantifiers, anchored: linear time
// eslint-disable-next-line security/detect-unsafe-regex
const NAME = /^[A-Za-z0-9_-]{1,128}$/, CIDR = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/, ROLE = /^[\w+=,.@-]{1,64}$/;

export function wafFiles(r: WafRuleSpec): HclFiles {
  if (!NAME.test(r.name)) throw new Error('rule.name must match [A-Za-z0-9_-]{1,128}');
  if (!r.addresses?.length || r.addresses.some((a) => !CIDR.test(a))) throw new Error('rule.addresses must be a non-empty list of IPv4 CIDRs');
  const action = (r.action ?? 'block').toLowerCase();
  if (!['block', 'allow', 'count'].includes(action)) throw new Error('rule.action must be block, allow or count');
  const scope = r.scope ?? 'REGIONAL', prio = Number.isInteger(r.priority) ? r.priority! : 100;
  return { 'main.tf': `resource "aws_wafv2_ip_set" "offenders" {
  name               = ${hclStr(`${r.name}-ips`)}
  scope              = ${hclStr(scope)}
  ip_address_version = "IPV4"
  addresses          = [${r.addresses.map(hclStr).join(', ')}]
}

resource "aws_wafv2_rule_group" "rules" {
  name     = ${hclStr(r.name)}
  scope    = ${hclStr(scope)}
  capacity = 10

  rule {
    name     = ${hclStr(r.name)}
    priority = ${prio}

    action {
      ${action} {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.offenders.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = ${hclStr(r.name)}
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = ${hclStr(`${r.name}-group`)}
    sampled_requests_enabled   = true
  }
}
` };
}

/**
 * With `replacePolicyName` the existing broad inline policy is IMPORTED and its document replaced in place, so the plan shows
 * exactly "this policy changes from broad to least-privilege". Without it a new inline policy is created.
 */
export function iamFiles(s: IamSpec): HclFiles {
  if (!ROLE.test(s.roleName)) throw new Error('invalid roleName');
  if (!s.proposed?.statements?.length) throw new Error('refusing an empty policy (it would lock the role out)');
  if (s.replacePolicyName && !/^[\w+=,.@-]{1,128}$/.test(s.replacePolicyName)) throw new Error('invalid replacePolicyName');
  const name = s.replacePolicyName ?? 'sentinelmesh-least-privilege';
  const doc = JSON.stringify({ Version: s.proposed.version, Statement: s.proposed.statements.map((x) => ({ Effect: x.effect, Action: x.actions, Resource: x.resources })) }, null, 2);
  const imp = s.replacePolicyName ? `import {
  to = aws_iam_role_policy.least_privilege
  id = ${hclStr(`${s.roleName}:${s.replacePolicyName}`)}
}

` : '';
  return { 'main.tf': `${imp}resource "aws_iam_role_policy" "least_privilege" {
  name   = ${hclStr(name)}
  role   = ${hclStr(s.roleName)}
  policy = ${heredoc('POLICY', doc)}
}
` };
}

export const filesHash = (f: HclFiles) => createHash('sha256').update(JSON.stringify(Object.keys(f).sort().map((k) => [k, f[k]]))).digest('hex');
