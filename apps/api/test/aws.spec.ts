import { S3Client, CreateBucketCommand } from '@aws-sdk/client-s3';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { WAFV2Client, ListIPSetsCommand, GetIPSetCommand, ListRuleGroupsCommand } from '@aws-sdk/client-wafv2';
import { IAMClient, CreateRoleCommand, PutRolePolicyCommand, GetRolePolicyCommand, ListRolePoliciesCommand } from '@aws-sdk/client-iam';
import { EC2Client, RunInstancesCommand, CreateSecurityGroupCommand, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { S3ObjectStorage, AwsSecretProvider, AwsInfraAdapter } from '../src/adapters/aws';
import { ApprovalSigner, HmacBackend } from '../src/approvals/signer';
import { ApprovalProof } from '../src/workflow/ports';

const endpoint = process.env.AWS_TEST_ENDPOINT; // moto_server (AWS API emulator)
const cfg = { endpoint, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' } };
const signer = new ApprovalSigner().use(new HmacBackend(Buffer.from('k')));
const check = (p: ApprovalProof) => signer.assertProof(p);
async function proof(planHash = 'h'): Promise<ApprovalProof> {
  const a = { id: 'apr', planId: 'pl', planHash }; const at = new Date().toISOString();
  return { approvalId: 'apr', planId: 'pl', planHash, decidedBy: 'u', decidedAt: at, signature: await signer.sign(a, 'approved', 'u', at) };
}
const bad: ApprovalProof = { approvalId: 'apr', planId: 'pl', planHash: 'h', decidedBy: 'u', decidedAt: 'x', signature: 'ff'.repeat(32) };

(endpoint ? describe : describe.skip)('AWS adapters against an AWS API emulator (needs AWS_TEST_ENDPOINT)', () => {
  beforeAll(async () => { await fetch(`${endpoint}/moto-api/reset`, { method: 'POST' }); });
  it('S3ObjectStorage round-trips and reports missing keys', async () => {
    const s3 = new S3Client({ ...cfg, forcePathStyle: true });
    await s3.send(new CreateBucketCommand({ Bucket: 'sm-evidence' }));
    const st = new S3ObjectStorage(s3, 'sm-evidence', 'prod/');
    await st.put('forensics/o/inc.json', '{"a":1}');
    expect((await st.get('forensics/o/inc.json'))!.toString()).toBe('{"a":1}');
    expect(await st.get('nope')).toBeUndefined();
  });

  it('Secrets Manager: idempotent create, active switch, rollback, and revoke only with proof', async () => {
    const sp = new AwsSecretProvider(new SecretsManagerClient(cfg), check);
    const id = `cred-${Date.now()}`;
    await sp.adopt(id, 'initial');
    expect(await sp.getActive(id)).toBe(1);
    const a = await sp.createVersion(id, 'exe1:create'); const again = await sp.createVersion(id, 'exe1:create');
    expect(a.version).toBe(2); expect(again.version).toBe(2);              // replay-safe
    expect(await sp.getActive(id)).toBe(1);                                 // creating does not switch consumers
    await sp.setActive(id, 2);
    expect(await sp.getActive(id)).toBe(2);
    expect(await sp.getValue(id, 1)).toBe('initial');                       // old still readable/valid → instant rollback possible
    await sp.setActive(id, 1); expect(await sp.getActive(id)).toBe(1);      // rollback
    await sp.setActive(id, 2);
    await expect(sp.revokeVersion(id, 1, bad)).rejects.toThrow(/approval proof/);
    expect(await sp.isValid(id, 1)).toBe(true);
    await expect(sp.revokeVersion(id, 2, await proof())).rejects.toThrow(/active/);
    await sp.revokeVersion(id, 1, await proof());
    expect(await sp.isValid(id, 1)).toBe(false);
    expect(await sp.isValid(id, 2)).toBe(true);
    await sp.revokeVersion(id, 1, await proof());                           // idempotent
    const dud = await sp.createVersion(id, 'exe2:create'); await sp.discardVersion(id, dud.version);
    expect(await sp.isValid(id, dud.version)).toBe(false);
  });

  it('WAFv2: needs proof, creates then idempotently updates ip set + rule group', async () => {
    const waf = new WAFV2Client(cfg);
    const infra = new AwsInfraAdapter({ waf, iam: new IAMClient(cfg), ec2: new EC2Client(cfg), proofCheck: check, isolation: {} });
    const params = { rule: { name: 'block-brute', action: 'block', priority: 5, addresses: ['203.0.113.9/32'] } };
    await expect(infra.applyWafRule(params, bad)).rejects.toThrow(/approval proof/);
    expect((await waf.send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups ?? []).toHaveLength(0);
    await infra.applyWafRule(params, await proof());
    await infra.applyWafRule({ rule: { ...params.rule, addresses: ['198.51.100.0/24'] } }, await proof());
    const ip = (await waf.send(new ListIPSetsCommand({ Scope: 'REGIONAL' }))).IPSets!.find((s) => s.Name === 'block-brute-ips')!;
    expect((await waf.send(new GetIPSetCommand({ Name: ip.Name!, Scope: 'REGIONAL', Id: ip.Id! }))).IPSet!.Addresses!.sort()).toEqual(['198.51.100.0/24', '203.0.113.9/32']);
    expect((await waf.send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups!.filter((g) => g.Name === 'block-brute')).toHaveLength(1);
    await expect(infra.applyWafRule({ rule: { name: 'x', addresses: ['not-a-cidr'] } }, await proof())).rejects.toThrow(/CIDR/);
  });

  it('IAM: replaces a broad inline policy with the approved least-privilege one; refuses empty policies', async () => {
    const iam = new IAMClient(cfg);
    await iam.send(new CreateRoleCommand({ RoleName: 'billing-role', AssumeRolePolicyDocument: JSON.stringify({ Version: '2012-10-17', Statement: [] }) }));
    await iam.send(new PutRolePolicyCommand({ RoleName: 'billing-role', PolicyName: 'broad', PolicyDocument: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:*', 'iam:*'], Resource: '*' }] }) }));
    const infra = new AwsInfraAdapter({ waf: new WAFV2Client(cfg), iam, ec2: new EC2Client(cfg), proofCheck: check, isolation: {} });
    const proposed = { version: '2012-10-17', statements: [{ effect: 'Allow', actions: ['s3:GetObject'], resources: ['arn:aws:s3:::billing/*'] }] };
    await expect(infra.applyIamPolicy({ roleName: 'billing-role', proposed }, bad)).rejects.toThrow(/approval proof/);
    expect((await iam.send(new ListRolePoliciesCommand({ RoleName: 'billing-role' }))).PolicyNames).toEqual(['broad']);
    await expect(infra.applyIamPolicy({ roleName: 'billing-role', proposed: { version: '2012-10-17', statements: [] } }, await proof())).rejects.toThrow(/empty/);
    await infra.applyIamPolicy({ roleName: 'billing-role', proposed, replacePolicyName: 'broad' }, await proof());
    expect((await iam.send(new ListRolePoliciesCommand({ RoleName: 'billing-role' }))).PolicyNames).toEqual(['sentinelmesh-least-privilege']);
    const doc = (await iam.send(new GetRolePolicyCommand({ RoleName: 'billing-role', PolicyName: 'sentinelmesh-least-privilege' }))).PolicyDocument!;
    expect(JSON.parse(decodeURIComponent(doc)).Statement[0].Action).toEqual(['s3:GetObject']);
  });

  it('EC2: isolation moves instances to the quarantine SG and records the previous groups', async () => {
    const ec2 = new EC2Client(cfg);
    const sg = await ec2.send(new CreateSecurityGroupCommand({ GroupName: 'auth-api-quarantine', Description: 'q' }));
    const web = await ec2.send(new CreateSecurityGroupCommand({ GroupName: 'auth-api-web', Description: 'w' }));
    const run = await ec2.send(new RunInstancesCommand({ ImageId: 'ami-12345678', MinCount: 1, MaxCount: 1, SecurityGroupIds: [web.GroupId!] }));
    const id = run.Instances![0].InstanceId!;
    const infra = new AwsInfraAdapter({ waf: new WAFV2Client(cfg), iam: new IAMClient(cfg), ec2, proofCheck: check, isolation: { 'auth-api': { instanceIds: [id], quarantineSecurityGroupId: sg.GroupId! } } });
    await expect(infra.isolateService('auth-api', bad)).rejects.toThrow(/approval proof/);
    await expect(infra.isolateService('unknown', await proof())).rejects.toThrow(/no isolation target/);
    await infra.isolateService('auth-api', await proof());
    await infra.isolateService('auth-api', await proof()); // idempotent
    const inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations![0].Instances![0];
    expect(inst.SecurityGroups!.map((g) => g.GroupId)).toEqual([sg.GroupId]);
    expect(inst.Tags!.find((t) => t.Key === 'sentinelmesh:previous-sgs')!.Value).toBe(web.GroupId); // survives the idempotent re-run
  });
});
