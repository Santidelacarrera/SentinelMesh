import { EC2Client, RunInstancesCommand } from '@aws-sdk/client-ec2';
import { S3Client, CreateBucketCommand } from '@aws-sdk/client-s3';
import { IAMClient, CreateUserCommand, CreateAccessKeyCommand, AttachUserPolicyCommand, CreatePolicyCommand } from '@aws-sdk/client-iam';
import { aws } from '../src/connectors/cloud';

const endpoint = process.env.AWS_TEST_ENDPOINT; // moto (emulates the AWS API; it is NOT AWS)
(endpoint ? describe : describe.skip)('AWS connector through the real AWS SDK against the moto emulator (needs AWS_TEST_ENDPOINT)', () => {
  const creds = { access_key_id: 'test', secret_access_key: 'test', region: 'us-east-1' };
  const cfg = { region: 'us-east-1', endpoint, credentials: { accessKeyId: 'test', secretAccessKey: 'test' } };
  beforeAll(async () => { await fetch(`${endpoint}/moto-api/reset`, { method: 'POST' }); });   // moto keeps state between runs
  it('reads EC2 instances, S3 buckets and IAM users with the production SDK code path', async () => {
    const ec2 = new EC2Client(cfg), s3 = new S3Client({ ...cfg, forcePathStyle: true }), iam = new IAMClient(cfg);
    await ec2.send(new RunInstancesCommand({ ImageId: 'ami-12c6146b', MinCount: 1, MaxCount: 1, TagSpecifications: [{ ResourceType: 'instance', Tags: [{ Key: 'Name', Value: 'web-moto' }] }] }));
    await s3.send(new CreateBucketCommand({ Bucket: 'sm-test-bucket' }));
    await iam.send(new CreateUserCommand({ UserName: 'deploy-bot' })); await iam.send(new CreateAccessKeyCommand({ UserName: 'deploy-bot' }));
    const pol = await iam.send(new CreatePolicyCommand({ PolicyName: 'AdministratorAccess', PolicyDocument: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }) }));
    await iam.send(new AttachUserPolicyCommand({ UserName: 'deploy-bot', PolicyArn: pol.Policy!.Arn! }));
    const rd = aws.reader!(creds, endpoint);
    expect(await rd.caller()).toMatch(/EC2/);
    expect((await rd.instances()).map((i) => i.name)).toContain('web-moto');
    expect((await rd.buckets()).map((b) => b.name)).toContain('sm-test-bucket');
    const u = (await rd.users()).find((x) => x.name === 'deploy-bot');
    expect(u).toMatchObject({ mfa: false, policies: ['AdministratorAccess'] }); expect(u!.keyAgeDays).toBeGreaterThanOrEqual(0);
  });
});
