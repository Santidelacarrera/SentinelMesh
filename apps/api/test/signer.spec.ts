import { generateKeyPairSync } from 'node:crypto';
import { KMSClient, CreateKeyCommand } from '@aws-sdk/client-kms';
import { ApprovalSigner, Ed25519Backend, HmacBackend, KmsBackend, backendFromEnv } from '../src/approvals/signer';

const a = { id: 'apr_1', planId: 'plan_1', planHash: 'abc' };
const when = '2026-01-01T00:00:00.000Z';
const AWS_URL = process.env.AWS_TEST_ENDPOINT;
const creds = { accessKeyId: 'test', secretAccessKey: 'test' };

async function roundtrip(s: ApprovalSigner) {
  const signature = await s.sign(a, 'approved', 'u1', when);
  const ap = { ...a, orgId: 'o', executionId: 'e', stepName: 's', status: 'approved' as const, requestedAt: when, decidedBy: 'u1', decidedAt: when, signature };
  expect(await s.verifyApproval(ap)).toBe(true);
  expect(await s.verifyApproval({ ...ap, planHash: 'evil' })).toBe(false);          // plan swap
  expect(await s.verifyApproval({ ...ap, decidedBy: 'u2' })).toBe(false);           // identity swap
  expect(await s.verifyApproval({ ...ap, signature: 'ab'.repeat(32) })).toBe(false); // forged
  const rejectedSig = await s.sign(a, 'rejected', 'u1', when);
  expect(await s.verifyApproval({ ...ap, signature: rejectedSig })).toBe(false);     // a rejection signature can't be replayed as approval
  await expect(s.assertProof(undefined)).rejects.toThrow(/approval proof/);
  await expect(s.assertProof(s.toProof(ap))).resolves.toBeUndefined();
}

describe('approval signature backends', () => {
  it('hmac', async () => roundtrip(new ApprovalSigner().use(new HmacBackend(Buffer.from('k')))));
  it('ed25519: a verify-only instance (public key) accepts but cannot sign', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const priv = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(); const pub = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    await roundtrip(new ApprovalSigner().use(new Ed25519Backend(priv)));
    const signature = await new Ed25519Backend(priv).sign(Buffer.from('x'));
    const verifier = new Ed25519Backend(undefined, pub);
    expect(await verifier.verify(Buffer.from('x'), signature)).toBe(true);
    await expect(verifier.sign(Buffer.from('x'))).rejects.toThrow(/verify/);
  });
  it('backendFromEnv refuses to start in production without a key', () => {
    expect(() => backendFromEnv({ NODE_ENV: 'production' } as any)).toThrow();
    expect(backendFromEnv({ APPROVAL_SIGNING_KEY: 'x' } as any).name).toBe('hmac-sha256');
  });
  (AWS_URL ? it : it.skip)('aws kms (asymmetric ECDSA)', async () => {
    const kms = new KMSClient({ endpoint: AWS_URL, region: 'us-east-1', credentials: creds });
    const k = await kms.send(new CreateKeyCommand({ KeySpec: 'ECC_NIST_P256', KeyUsage: 'SIGN_VERIFY' }));
    await roundtrip(new ApprovalSigner().use(new KmsBackend(kms, k.KeyMetadata!.KeyId!)));
  });
});
