import { createHash, randomBytes } from 'node:crypto';
import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
  CreateSecretCommand, DescribeSecretCommand, GetSecretValueCommand, PutSecretValueCommand, SecretsManagerClient, UpdateSecretVersionStageCommand, ResourceNotFoundException,
} from '@aws-sdk/client-secrets-manager';
import { CreateIPSetCommand, CreateRuleGroupCommand, GetIPSetCommand, GetRuleGroupCommand, ListIPSetsCommand, ListRuleGroupsCommand, UpdateIPSetCommand, UpdateRuleGroupCommand, WAFV2Client } from '@aws-sdk/client-wafv2';
import { DeleteRolePolicyCommand, IAMClient, PutRolePolicyCommand } from '@aws-sdk/client-iam';
import { CreateTagsCommand, DescribeInstancesCommand, EC2Client, ModifyInstanceAttributeCommand } from '@aws-sdk/client-ec2';
import { ObjectStorage } from '../storage/object-storage';
import { ApprovalProof, InfraAdapter, SecretProvider } from '../workflow/ports';

type ProofCheck = (p: ApprovalProof) => void | Promise<void>;

// ───────────────────────────── S3 / MinIO ─────────────────────────────
export class S3ObjectStorage implements ObjectStorage {
  constructor(private s3: S3Client, private bucket: string, private prefix = '') {}
  async put(key: string, body: Buffer | string) { await this.s3.send(new PutObjectCommand({ Bucket: this.bucket, Key: this.prefix + key, Body: body, ServerSideEncryption: undefined })); }
  async get(key: string) {
    try { const r = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: this.prefix + key })); return Buffer.from(await r.Body!.transformToByteArray()); }
    catch (e) { if ((e as { name?: string }).name === 'NoSuchKey') return undefined; throw e; }
  }
}

// ───────────────────────── Secrets Manager ─────────────────────────
/** Issues/revokes the credential at the system that owns it (IAM key, DB user, API vendor…). */
export interface CredentialIssuer { issue(credentialId: string, version: number): Promise<string>; revoke(credentialId: string, version: number, value: string | undefined): Promise<void> }
export const randomIssuer: CredentialIssuer = { issue: async () => randomBytes(32).toString('base64url'), revoke: async () => {} };

const uuidFrom = (s: string) => { const h = createHash('sha256').update(s).digest('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`; };
const label = (v: number) => `sm-v${v}`;

/**
 * SecretProvider on AWS Secrets Manager. Our integer versions are staging labels `sm-vN`; AWSCURRENT is the active one.
 *  - createVersion is idempotent: ClientRequestToken is derived from the idempotency key, so a replay returns the same version.
 *  - revokeVersion removes the label (version becomes deprecated) after the issuer revokes it; needs a verified approval proof.
 */
export class AwsSecretProvider implements SecretProvider {
  constructor(private sm: SecretsManagerClient, private proofCheck: ProofCheck, private issuer: CredentialIssuer = randomIssuer, private prefix = 'sentinelmesh/') {}
  private name(id: string) { return this.prefix + id; }

  private async describe(id: string) {
    try { return await this.sm.send(new DescribeSecretCommand({ SecretId: this.name(id) })); }
    catch (e) { if (e instanceof ResourceNotFoundException) return undefined; throw e; }
  }
  private versionOf(stages: string[]) { const l = stages.find((s) => /^sm-v\d+$/.test(s)); return l ? Number(l.slice(4)) : undefined; }

  /** Registers an existing secret as v1 (or creates it). Safe to call repeatedly. */
  async adopt(id: string, initialValue?: string) {
    const d = await this.describe(id);
    if (!d) { await this.sm.send(new CreateSecretCommand({ Name: this.name(id), SecretString: initialValue ?? await this.issuer.issue(id, 1) })); }
    await this.ensureLabelled(id);
  }
  private async ensureLabelled(id: string) {
    const d = (await this.describe(id))!;
    for (const [vid, stages] of Object.entries(d.VersionIdsToStages ?? {})) {
      if (stages.includes('AWSCURRENT') && this.versionOf(stages) === undefined)
        await this.sm.send(new UpdateSecretVersionStageCommand({ SecretId: this.name(id), VersionStage: label(1), MoveToVersionId: vid }));
    }
  }
  private async versions(id: string) {
    const d = await this.describe(id); const out = new Map<number, { vid: string; current: boolean }>();
    for (const [vid, stages] of Object.entries(d?.VersionIdsToStages ?? {})) { const n = this.versionOf(stages); if (n !== undefined) out.set(n, { vid, current: stages.includes('AWSCURRENT') }); }
    return out;
  }

  async createVersion(id: string, key: string) {
    await this.ensureLabelled(id);
    const token = uuidFrom(key); const d = await this.describe(id);
    const existing = d?.VersionIdsToStages?.[token];
    if (existing) { const n = this.versionOf(existing); if (n !== undefined) return { version: n }; }
    const next = Math.max(0, ...(await this.versions(id)).keys()) + 1;
    await this.sm.send(new PutSecretValueCommand({ SecretId: this.name(id), SecretString: await this.issuer.issue(id, next), ClientRequestToken: token, VersionStages: [label(next)] }));
    return { version: next };
  }
  async setActive(id: string, v: number) {
    const vs = await this.versions(id); const t = vs.get(v); if (!t) throw new Error(`version ${v} not found`);
    if (t.current) return;
    const cur = [...vs.values()].find((x) => x.current);
    await this.sm.send(new UpdateSecretVersionStageCommand({ SecretId: this.name(id), VersionStage: 'AWSCURRENT', MoveToVersionId: t.vid, RemoveFromVersionId: cur?.vid }));
  }
  async getActive(id: string) {
    await this.ensureLabelled(id);
    for (const [n, x] of await this.versions(id)) if (x.current) return n;
    throw new Error('no active version');
  }
  async discardVersion(id: string, v: number) {
    const t = (await this.versions(id)).get(v); if (!t) return;
    if (t.current) throw new Error('refusing to discard the active version');
    await this.sm.send(new UpdateSecretVersionStageCommand({ SecretId: this.name(id), VersionStage: label(v), RemoveFromVersionId: t.vid }));
  }
  async revokeVersion(id: string, v: number, proof: ApprovalProof) {
    await this.proofCheck(proof);
    const t = (await this.versions(id)).get(v); if (!t) return; // already gone: idempotent
    if (t.current) throw new Error('refusing to revoke the active version');
    let value: string | undefined;
    try { value = (await this.sm.send(new GetSecretValueCommand({ SecretId: this.name(id), VersionId: t.vid }))).SecretString; } catch { /* unreadable → still revoke */ }
    await this.issuer.revoke(id, v, value);
    await this.sm.send(new UpdateSecretVersionStageCommand({ SecretId: this.name(id), VersionStage: label(v), RemoveFromVersionId: t.vid }));
  }
  async isValid(id: string, v: number) { return (await this.versions(id)).has(v); }
  /** For health checkers: the secret material of a version. Never log the result. */
  async getValue(id: string, v: number) {
    const t = (await this.versions(id)).get(v); if (!t) throw new Error(`version ${v} not found`);
    return (await this.sm.send(new GetSecretValueCommand({ SecretId: this.name(id), VersionId: t.vid }))).SecretString!;
  }
}

// ───────────────────────── WAFv2 · IAM · EC2 ─────────────────────────
export interface IsolationTarget { instanceIds: string[]; quarantineSecurityGroupId: string }

/**
 * Real infrastructure changes. Every method verifies the approval proof FIRST, and operations are idempotent
 * (re-running after a crash converges to the same state).
 */
export class AwsInfraAdapter implements InfraAdapter {
  constructor(private o: { waf: WAFV2Client; iam: IAMClient; ec2: EC2Client; proofCheck: ProofCheck; isolation: Record<string, IsolationTarget>; wafScope?: 'REGIONAL' | 'CLOUDFRONT' }) {}
  private scope() { return this.o.wafScope ?? 'REGIONAL'; }

  /** params.rule = { name, action: block|allow|count, priority, addresses: CIDR[] }. Creates/updates an IP set and a rule group that references it. */
  async applyWafRule(params: Record<string, unknown>, proof: ApprovalProof) {
    await this.o.proofCheck(proof);
    const rule = params['rule'] as { name?: string; action?: string; priority?: number; addresses?: string[] } | undefined;
    if (!rule?.name || !/^[\w-]{1,128}$/.test(rule.name)) throw new Error('rule.name is required ([A-Za-z0-9_-])');
    const addresses = rule.addresses ?? []; if (!addresses.length || addresses.some((a) => !/^[\d.]+\/\d{1,2}$/.test(a))) throw new Error('rule.addresses must be IPv4 CIDRs');
    const action = (rule.action ?? 'block').toLowerCase(); if (!['block', 'allow', 'count'].includes(action)) throw new Error('invalid action');
    const scope = this.scope(); const ipName = `${rule.name}-ips`;

    let ip = (await this.o.waf.send(new ListIPSetsCommand({ Scope: scope }))).IPSets?.find((s) => s.Name === ipName);
    if (!ip) ip = (await this.o.waf.send(new CreateIPSetCommand({ Name: ipName, Scope: scope, IPAddressVersion: 'IPV4', Addresses: addresses }))).Summary!;
    else {
      const cur = await this.o.waf.send(new GetIPSetCommand({ Name: ipName, Scope: scope, Id: ip.Id! }));
      const merged = [...new Set([...(cur.IPSet?.Addresses ?? []), ...addresses])];
      await this.o.waf.send(new UpdateIPSetCommand({ Name: ipName, Scope: scope, Id: ip.Id!, Addresses: merged, LockToken: cur.LockToken! }));
    }
    const actionObj = action === 'block' ? { Block: {} } : action === 'allow' ? { Allow: {} } : { Count: {} };
    const rules = [{ Name: rule.name, Priority: rule.priority ?? 100, Action: actionObj, Statement: { IPSetReferenceStatement: { ARN: ip.ARN! } },
      VisibilityConfig: { SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: rule.name } }];
    const existing = (await this.o.waf.send(new ListRuleGroupsCommand({ Scope: scope }))).RuleGroups?.find((g) => g.Name === rule.name);
    if (!existing) {
      const g = await this.o.waf.send(new CreateRuleGroupCommand({ Name: rule.name, Scope: scope, Capacity: 10, Rules: rules, VisibilityConfig: { SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: `${rule.name}-group` } }));
      return { ref: g.Summary!.ARN! };
    }
    const cur = await this.o.waf.send(new GetRuleGroupCommand({ Name: rule.name, Scope: scope, Id: existing.Id! }));
    await this.o.waf.send(new UpdateRuleGroupCommand({ Name: rule.name, Scope: scope, Id: existing.Id!, Rules: rules, VisibilityConfig: cur.RuleGroup!.VisibilityConfig!, LockToken: cur.LockToken! }));
    return { ref: existing.ARN! };
  }

  /** params = { roleName, proposed: PolicyDoc, replacePolicyName? }. Writes the least-privilege inline policy, then removes the broad one. */
  async applyIamPolicy(params: Record<string, unknown>, proof: ApprovalProof) {
    await this.o.proofCheck(proof);
    const roleName = String(params['roleName'] ?? ''); const proposed = params['proposed'] as { version: string; statements: Array<{ effect: string; actions: string[]; resources: string[] }> } | undefined;
    if (!/^[\w+=,.@-]{1,64}$/.test(roleName)) throw new Error('invalid roleName');
    if (!proposed?.statements?.length) throw new Error('refusing to apply an empty policy (would lock the role out); use an explicit detach flow instead');
    const doc = { Version: proposed.version, Statement: proposed.statements.map((s) => ({ Effect: s.effect, Action: s.actions, Resource: s.resources })) };
    const name = 'sentinelmesh-least-privilege';
    await this.o.iam.send(new PutRolePolicyCommand({ RoleName: roleName, PolicyName: name, PolicyDocument: JSON.stringify(doc) }));
    const old = params['replacePolicyName'] as string | undefined;
    if (old && old !== name) await this.o.iam.send(new DeleteRolePolicyCommand({ RoleName: roleName, PolicyName: old }));
    return { ref: `${roleName}/${name}` };
  }

  /** Moves the service's instances to the quarantine SG (no egress, bastion-only ingress). Previous SGs are stored in a tag for rollback. */
  async isolateService(target: string, proof: ApprovalProof) {
    await this.o.proofCheck(proof);
    const t = this.o.isolation[target]; if (!t) throw new Error(`no isolation target configured for "${target}"`);
    const res = await this.o.ec2.send(new DescribeInstancesCommand({ InstanceIds: t.instanceIds }));
    for (const inst of res.Reservations?.flatMap((r) => r.Instances ?? []) ?? []) {
      const prev = (inst.SecurityGroups ?? []).map((g) => g.GroupId!).filter((g) => g !== t.quarantineSecurityGroupId);
      if (prev.length) await this.o.ec2.send(new CreateTagsCommand({ Resources: [inst.InstanceId!], Tags: [{ Key: 'sentinelmesh:previous-sgs', Value: prev.join(',') }] }));
      await this.o.ec2.send(new ModifyInstanceAttributeCommand({ InstanceId: inst.InstanceId!, Groups: [t.quarantineSecurityGroupId] }));
    }
    return { ref: `isolated:${target}:${t.instanceIds.join(',')}` };
  }
}
