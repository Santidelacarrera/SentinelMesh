import { Test } from '@nestjs/testing';
import request from 'supertest';
import { IAMClient, CreateRoleCommand, PutRolePolicyCommand, ListRolePoliciesCommand, GetRolePolicyCommand } from '@aws-sdk/client-iam';
import { WAFV2Client, ListRuleGroupsCommand, ListIPSetsCommand, GetIPSetCommand } from '@aws-sdk/client-wafv2';
import { EC2Client } from '@aws-sdk/client-ec2';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AppModule } from '../src/app.module';
import { JOB_QUEUE, MemoryQueue } from '../src/queue/queue';
import { EXECUTION_LOCK, MemoryLock } from '../src/workflow/lock';
import { MemoryObjectStorage, OBJECT_STORAGE } from '../src/storage/object-storage';
import { PORTS } from '../src/workflow/ports';
import { ApprovalSigner } from '../src/approvals/signer';
import { AwsInfraAdapter } from '../src/adapters/aws';
import { TerraformInfraAdapter } from '../src/terraform/infra';
import { TerraformPlanner } from '../src/terraform/planner';
import { TerraformRunner } from '../src/terraform/runner';
import { wafFiles, iamFiles, hclStr } from '../src/terraform/hcl';
import { Db } from '../src/store/db';
import './helpers';

const endpoint = process.env.AWS_TEST_ENDPOINT, bin = process.env.TF_TEST_BIN;
const cfg = { endpoint, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' } };
const tfCfg = () => ({
  bin: bin!, stateDir: mkdtempSync(join(tmpdir(), 'smstate-')), cliConfigFile: process.env.TF_TEST_RC, awsProviderVersion: process.env.TF_TEST_AWS_VERSION ?? '~> 5.0', timeoutMs: 240_000,
  providerHcl: `provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  endpoints {
    wafv2 = "${endpoint}"
    iam   = "${endpoint}"
    sts   = "${endpoint}"
  }
}
`,
});

describe('HCL generation (no terraform needed)', () => {
  it('escapes template syntax and rejects hostile input', () => {
    expect(hclStr('a${b}"c%{x}')).toBe('"a$${b}\\"c%%{x}"');
    expect(() => wafFiles({ name: 'x"}\nresource "aws_s3_bucket" "evil" {', addresses: ['1.1.1.1/32'] })).toThrow(/rule.name/);
    expect(() => wafFiles({ name: 'ok', addresses: ['1.1.1.1/32"]\n}'] })).toThrow(/CIDR/);
    expect(() => wafFiles({ name: 'ok', addresses: ['1.1.1.1/32'], action: 'block {}\n}' })).toThrow(/action/);
    expect(() => iamFiles({ roleName: 'r"; x', proposed: { version: '2012-10-17', statements: [{ effect: 'Allow', actions: ['s3:Get*'], resources: ['*'] }] } })).toThrow(/roleName/);
    expect(() => iamFiles({ roleName: 'r', proposed: { version: '2012-10-17', statements: [] } })).toThrow(/empty/);
    const f = iamFiles({ roleName: 'r', replacePolicyName: 'broad', proposed: { version: '2012-10-17', statements: [{ effect: 'Allow', actions: ['s3:GetObject'], resources: ['arn:aws:s3:::b/${aws:username}/*'] }] } });
    expect(f['main.tf']).toContain('$${aws:username}');            // IAM policy variables survive as literal text
    expect(f['main.tf']).toContain('import {');
  });
});

((endpoint && bin) ? describe : describe.skip)('real Terraform plan/apply against an AWS API emulator (needs TF_TEST_BIN + AWS_TEST_ENDPOINT)', () => {
  beforeEach(async () => { await fetch(`${endpoint}/moto-api/reset`, { method: 'POST' }); });
  jest.setTimeout(300_000);

  it('runner: plan is read-only, deterministic, and reports the exact resource changes', async () => {
    const r = new TerraformRunner(tfCfg());
    const files = wafFiles({ name: 'block-brute', addresses: ['203.0.113.0/24'], priority: 5 });
    const a = await r.plan('t-waf', files), b = await r.plan('t-waf', files);
    expect(a.summary).toEqual({ add: 2, change: 0, destroy: 0 });
    expect(a.text).toContain('will be created');
    expect(a.changesHash).toBe(b.changesHash);                                                       // same input ⇒ same hash (approval can bind to it)
    expect((await new WAFV2Client(cfg).send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups ?? []).toHaveLength(0);   // planning created nothing
    await expect(r.plan('t-bad', { 'main.tf': 'resource "aws_wafv2_ip_set" "x" { name = ' })).rejects.toThrow(/terraform (init|validate|plan) failed/);
  });

  async function app(planner: TerraformPlanner, st: MemoryObjectStorage) {
    const mod = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(JOB_QUEUE).useValue(new MemoryQueue(3, 0)).overrideProvider(EXECUTION_LOCK).useValue(new MemoryLock()).overrideProvider(OBJECT_STORAGE).useValue(st)
      .overrideProvider(TerraformPlanner).useValue(planner)
      .overrideProvider(PORTS.INFRA).useFactory({ inject: [ApprovalSigner], factory: (s: ApprovalSigner) =>
        new TerraformInfraAdapter(new AwsInfraAdapter({ waf: new WAFV2Client(cfg), iam: new IAMClient(cfg), ec2: new EC2Client(cfg), isolation: {}, proofCheck: (p) => s.assertProof(p) }), planner, (p) => s.assertProof(p)) })
      .compile();
    const a = mod.createNestApplication(); await a.init();
    return { a, h: request(a.getHttpServer()), q: mod.get<MemoryQueue>(JOB_QUEUE), db: mod.get(Db), st };
  }
  const post = (h: ReturnType<typeof request>, key: string, path: string, body: object) => h.post(path).set('x-api-key', key).send(body);

  it('WAF: the analyst sees a real plan, nothing exists until approval, then exactly that plan is applied (and replay is a no-op)', async () => {
    const st = new MemoryObjectStorage(), planner = new TerraformPlanner(st, tfCfg()), { a, h, q, db } = await app(planner, st);
    const sim = await post(h, 'dev-analyst', '/api/v1/remediations/simulate', { kind: 'waf', targetRef: 'payments-gateway', submitForApproval: true, params: { rule: { name: 'block-sqli', action: 'block', priority: 10, addresses: ['203.0.113.0/24', '198.51.100.17/32'] } } }).expect(201);
    expect(sim.body.plan.tf.summary).toEqual({ add: 2, change: 0, destroy: 0 });
    expect(sim.body.plan.tf.text).toContain('aws_wafv2_rule_group.rules will be created');
    expect(sim.body.plan.terraform).toContain('resource "aws_wafv2_ip_set" "offenders"');
    await q.idle();
    const waf = new WAFV2Client(cfg);
    expect((await waf.send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups ?? []).toHaveLength(0);
    const [apr] = await db.approvals.list('org_acme');
    expect(apr.planHash).toBe(sim.body.plan.planHash);
    await post(h, 'dev-approver', `/api/v1/approvals/${apr.id}/decision`, { decision: 'approved' }).expect(200);
    await q.idle();
    expect((await db.executions.get('org_acme', sim.body.executionId))!.status).toBe('succeeded');
    expect((await waf.send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups!.map((g) => g.Name)).toEqual(['block-sqli']);
    const ip = (await waf.send(new ListIPSetsCommand({ Scope: 'REGIONAL' }))).IPSets![0];
    expect((await waf.send(new GetIPSetCommand({ Name: ip.Name!, Scope: 'REGIONAL', Id: ip.Id! }))).IPSet!.Addresses!.sort()).toEqual(['198.51.100.17/32', '203.0.113.0/24']);
    // replay after "crash": the saved plan is stale because it was already applied → recognised as success, no duplicate resources
    const plan = (await db.plans.get('org_acme', sim.body.plan.id))!;
    await expect(planner.apply(plan)).resolves.toMatchObject({ alreadyApplied: true });
    expect((await waf.send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups).toHaveLength(1);
    await a.close();
  });

  it('refuses a tampered saved plan or altered HCL, and a hostile rule never reaches terraform', async () => {
    const st = new MemoryObjectStorage(), planner = new TerraformPlanner(st, tfCfg()), { a, h, q, db } = await app(planner, st);
    await post(h, 'dev-analyst', '/api/v1/remediations/simulate', { kind: 'waf', targetRef: 'gw', params: { rule: { name: 'x"}\nresource "aws_s3_bucket" "evil" {', addresses: ['1.1.1.1/32'] } } }).expect(400);
    const sim = await post(h, 'dev-analyst', '/api/v1/remediations/simulate', { kind: 'waf', targetRef: 'gw', submitForApproval: true, params: { rule: { name: 'safe', addresses: ['192.0.2.0/24'] } } }).expect(201);
    await q.idle();
    const plan = (await db.plans.get('org_acme', sim.body.plan.id))!;
    await st.put(plan.tf!.planRef!, Buffer.from('forged plan'));                       // swap the stored plan
    const [apr] = await db.approvals.list('org_acme');
    await post(h, 'dev-approver', `/api/v1/approvals/${apr.id}/decision`, { decision: 'approved' }).expect(200);
    await q.idle();
    expect((await db.executions.get('org_acme', sim.body.executionId))!.status).toBe('failed');
    expect((await new WAFV2Client(cfg).send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups ?? []).toHaveLength(0);
    // altered HCL after the plan was made is caught by the plan hash
    const sim2 = await post(h, 'dev-analyst', '/api/v1/remediations/simulate', { kind: 'waf', targetRef: 'gw', submitForApproval: true, params: { rule: { name: 'safe2', addresses: ['192.0.2.0/24'] } } }).expect(201);
    await q.idle();
    await db.plans.update('org_acme', sim2.body.plan.id, (p) => { p.tf!.files['main.tf'] += '\nresource "aws_wafv2_ip_set" "extra" {}\n'; });
    const apr2 = (await db.approvals.list('org_acme')).find((x) => x.planId === sim2.body.plan.id)!;
    await post(h, 'dev-approver', `/api/v1/approvals/${apr2.id}/decision`, { decision: 'approved' }).expect(200);
    await q.idle();
    expect((await db.executions.get('org_acme', sim2.body.executionId))!.status).toBe('failed');
    await a.close();
  });

  it('IAM: imports the broad inline policy and replaces it in place with the least-privilege document', async () => {
    const iam = new IAMClient(cfg);
    await iam.send(new CreateRoleCommand({ RoleName: 'billing-batch-role', AssumeRolePolicyDocument: JSON.stringify({ Version: '2012-10-17', Statement: [] }) }));
    await iam.send(new PutRolePolicyCommand({ RoleName: 'billing-batch-role', PolicyName: 'broad', PolicyDocument: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:*', 'iam:*'], Resource: '*' }] }) }));
    const st = new MemoryObjectStorage(), planner = new TerraformPlanner(st, tfCfg()), { a, h, q, db } = await app(planner, st);
    const r = await post(h, 'dev-analyst', '/api/v1/iam/audit-roles', { roleName: 'billing-batch-role', critical: true, grantedActions: ['s3:GetObject', 's3:PutObject', 'iam:PassRole'], auditEvents: ['s3:GetObject'], resources: ['arn:aws:s3:::billing/*'], submitForApproval: true }).expect(201);
    // the analyst did not name the broad policy: add it through a second simulate with replacePolicyName (the console passes it when known)
    const sim = await post(h, 'dev-analyst', '/api/v1/remediations/simulate', { kind: 'iam', targetRef: 'billing-batch-role', submitForApproval: true, params: { roleName: 'billing-batch-role', replacePolicyName: 'broad', current: { statements: [{ actions: ['s3:*', 'iam:*'] }] }, proposed: r.body.audit.proposedPolicy } }).expect(201);
    expect(sim.body.plan.tf.text).toMatch(/aws_iam_role_policy.least_privilege/);
    expect(sim.body.plan.tf.summary.add + sim.body.plan.tf.summary.change).toBeGreaterThan(0);
    await q.idle();
    const [before] = (await iam.send(new ListRolePoliciesCommand({ RoleName: 'billing-batch-role' }))).PolicyNames!;
    expect(before).toBe('broad');
    expect(JSON.parse(decodeURIComponent((await iam.send(new GetRolePolicyCommand({ RoleName: 'billing-batch-role', PolicyName: 'broad' }))).PolicyDocument!)).Statement[0].Action).toEqual(['s3:*', 'iam:*']);
    const apr = (await db.approvals.list('org_acme')).find((x) => x.planId === sim.body.plan.id)!;
    await post(h, 'dev-approver', `/api/v1/approvals/${apr.id}/decision`, { decision: 'approved' }).expect(200);
    await q.idle();
    expect((await db.executions.get('org_acme', sim.body.executionId))!.status).toBe('succeeded');
    const after = JSON.parse(decodeURIComponent((await iam.send(new GetRolePolicyCommand({ RoleName: 'billing-batch-role', PolicyName: 'broad' }))).PolicyDocument!));
    expect(after.Statement[0].Action).toEqual(['s3:GetObject']);
    await a.close();
  });
});
