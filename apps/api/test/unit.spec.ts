import { redact, redactString, maskSecret } from '../src/common/mask';
import { assertSafeUrl, isPrivateIp } from '../src/common/ssrf';
import { AuditTrail } from '../src/audit/audit-trail';
import { localCorrelate, localLeastPrivilege } from '../src/analytics/analytics.client';

describe('secret masking', () => {
  it('redacts well-known credential formats', () => {
    const s = 'key AKIAIOSFODNN7EXAMPLE token ghp_abcdefghijklmnopqrstuvwxyz0123456789 password=hunter2hunter2 Bearer abcdefghijklmnop12345';
    const r = redactString(s);
    expect(r).not.toMatch(/AKIAIOSFODNN7EXAMPLE|ghp_abc|hunter2|abcdefghijklmnop12345/);
  });
  it('redacts private keys and sensitive object keys deeply', () => {
    const r = redact({ a: { apiKey: 'sk-live-123456', note: '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----' } });
    expect(JSON.stringify(r)).not.toMatch(/sk-live|MIIE/);
  });
  it('maskSecret never returns the full secret', () => {
    expect(maskSecret('AKIAIOSFODNN7EXAMPLE')).toBe('AKIA****LE');
    expect(maskSecret('short')).toBe('*****');
  });
});

describe('SSRF defence', () => {
  it.each(['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.0.1', '172.20.0.5', '::1', 'fd00::1', '::ffff:127.0.0.1'])('flags %s private', (ip) => expect(isPrivateIp(ip)).toBe(true));
  it.each(['8.8.8.8', '93.184.216.34'])('allows public %s', (ip) => expect(isPrivateIp(ip)).toBe(false));
  it('rejects bad schemes, metadata IP, userinfo, and DNS names resolving privately', async () => {
    await expect(assertSafeUrl('file:///etc/passwd')).rejects.toThrow();
    await expect(assertSafeUrl('http://example.com')).rejects.toThrow('scheme');
    await expect(assertSafeUrl('https://169.254.169.254/latest')).rejects.toThrow('private');
    await expect(assertSafeUrl('https://user:pw@example.com')).rejects.toThrow('credentials');
    await expect(assertSafeUrl('https://evil.test', { resolve: async () => ['10.0.0.8'] })).rejects.toThrow('private');
    await expect(assertSafeUrl('https://ok.test', { resolve: async () => ['93.184.216.34'] })).resolves.toBeInstanceOf(URL);
    await expect(assertSafeUrl('https://ok.test', { allowedHosts: ['other.test'], resolve: async () => ['93.184.216.34'] })).rejects.toThrow('allowlist');
  });
});

describe('audit trail', () => {
  it('chains hashes, redacts payloads, and detects tampering', () => {
    const a = new AuditTrail();
    a.append('o', 'u', 'e1', { password: 'p4ssw0rd!' });
    a.append('o', 'u', 'e2', { note: 'AKIAIOSFODNN7EXAMPLE' });
    expect(JSON.stringify(a.list('o'))).not.toMatch(/p4ssw0rd|AKIAIOSFODNN7EXAMPLE/);
    expect(a.verify('o').ok).toBe(true);
    expect(() => { (a.list('o')[0] as any).event = 'tampered'; }).toThrow(); // frozen entries
    (a as any).chains.get('o')[0] = { ...a.list('o')[0], event: 'tampered' };
    expect(a.verify('o')).toEqual({ ok: false, brokenAt: 1 });
  });
});

describe('audit trail persistence round-trip', () => {
  it('a chain written with undefined fields still verifies after a JSON/JSONB round-trip (regression)', () => {
    const a = new AuditTrail();
    a.append('o', 'u1', 'approval.approved', { approvalId: 'x', comment: undefined, nested: { gone: undefined, kept: 1 } });
    a.append('o', 'u1', 'step.succeeded', { output: { v: undefined } });
    const b = new AuditTrail();
    b.hydrate(JSON.parse(JSON.stringify(a.list('o'))));        // what a JSONB column hands back: undefined keys are gone
    expect(b.verify('o')).toEqual({ ok: true });
  });
});

describe('local analytics fallback', () => {
  it('lowers exposure for gateway-protected dev assets and suppresses false positives', () => {
    const exposed = localCorrelate({ ruleId: 'r', kind: 'vulnerability', severity: 'high', asset: { internetFacing: true, behindGateway: false, handlesCriticalData: true, environment: 'prod' } });
    const shielded = localCorrelate({ ruleId: 'r', kind: 'vulnerability', severity: 'high', asset: { internetFacing: false, behindGateway: true, handlesCriticalData: false, environment: 'dev' } });
    expect(exposed.exposureScore).toBeGreaterThan(shielded.exposureScore);
    expect(localCorrelate({ ruleId: 'r', kind: 'secret', severity: 'high', likelyFalsePositive: true }).suppressed).toBe(true);
  });
  it('never downgrades a leaked secret', () => {
    const r = localCorrelate({ ruleId: 'aws', kind: 'secret', severity: 'critical', asset: { internetFacing: false, behindGateway: true, handlesCriticalData: false, environment: 'dev' } });
    expect(r.severity).toBe('critical');
  });
  it('least-privilege keeps only used actions', () => {
    const r = localLeastPrivilege(['s3:GetObject', 's3:PutObject', 's3:DeleteObject'], ['s3:GetObject', 's3:GetObject'], ['arn:aws:s3:::b/*']);
    expect(r.unused).toEqual(['s3:DeleteObject', 's3:PutObject']);
    expect(r.proposedPolicy.statements[0].actions).toEqual(['s3:GetObject']);
  });
});

describe('production guard', () => {
  it('refuses simulated ports in production', async () => {
    const { Test } = await import('@nestjs/testing'); const { AppModule } = await import('../src/app.module');
    const prev = { ...process.env }; process.env.NODE_ENV = 'production'; process.env.APPROVAL_SIGNING_KEY = 'k'; delete process.env.INFRA_MODE;
    try { await expect(Test.createTestingModule({ imports: [AppModule] }).compile()).rejects.toThrow(/INFRA_MODE=aws/); }
    finally { process.env = prev; }
  });
});

describe('placeholder detection (false-positive suppression for leaked-secret reports)', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { looksLikePlaceholder } = require('../src/ingest/parsers');
  it.each(['YOUR_API_KEY_HERE', 'your-token', 'changeme', 'dummy-secret-123', 'xxxxxxxxxxxx', 'abc_EXAMPLE_key', 'placeholder'])('%s is a placeholder', (s) => expect(looksLikePlaceholder(s)).toBe(true));
  it.each(['AKIAIOSFODNN7EXAMPLE', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'k3Zp9QvT1mXw', 'sk-test-9f8e7d6c'])('%s is not', (s) => expect(looksLikePlaceholder(s)).toBe(false));
  it('is linear on hostile input (no catastrophic backtracking)', () => {
    const t0 = Date.now(); looksLikePlaceholder('x'.repeat(4096) + '!'); looksLikePlaceholder('your_'.repeat(800));
    expect(Date.now() - t0).toBeLessThan(200);
  });
});

describe('FsObjectStorage', () => {
  it('refuses keys that escape its root', async () => {
    const { FsObjectStorage } = await import('../src/storage/object-storage');
    const { mkdtempSync } = await import('node:fs'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
    const root = mkdtempSync(join(tmpdir(), 'smfs-')); const st = new FsObjectStorage(root);
    await st.put('a/b.json', '{}'); expect((await st.get('a/b.json'))!.toString()).toBe('{}');
    await expect(st.put('../evil', 'x')).rejects.toThrow('invalid key');
    await st.put('/etc/passwd', 'x');                                   // an absolute-looking key is just a name under root…
    expect((await import('node:fs')).existsSync(join(root, 'etc/passwd'))).toBe(true);   // …it never reaches the real /etc
    await expect(st.put('a/../../evil', 'x')).rejects.toThrow('invalid key');
    expect(await st.get('../evil')).toBeUndefined();
  });
});

describe('core runs at cost $0 by default', () => {
  it('without INFRA_MODE every external port is the in-process simulation (no cloud client is built)', async () => {
    const { boot } = await import('./helpers');
    const { SimulatedSecrets, SimulatedInfra, SimulatedHealth, SimulatedForensics } = await import('../src/workflow/simulated');
    const { PORTS } = await import('../src/workflow/ports');
    const prev = process.env.INFRA_MODE; delete process.env.INFRA_MODE;
    const t = await boot();
    try {
      expect(t.app.get(PORTS.SECRETS)).toBeInstanceOf(SimulatedSecrets);
      expect(t.app.get(PORTS.INFRA)).toBeInstanceOf(SimulatedInfra);
      expect(t.app.get(PORTS.HEALTH)).toBeInstanceOf(SimulatedHealth);
      expect(t.app.get(PORTS.FORENSICS)).toBeInstanceOf(SimulatedForensics);
    } finally { if (prev) process.env.INFRA_MODE = prev; await t.app.close(); }
  });
});

describe('real entrypoint', () => {
  it('bootstrap() starts an HTTP server that answers /healthz and enforces authentication', async () => {
    process.env.NODE_ENV = 'test';
    const { bootstrap } = await import('../src/main');
    const app = await bootstrap(0);
    try {
      const base = (await app.getUrl()).replace('[::1]', '127.0.0.1');
      expect((await fetch(`${base}/healthz`)).status).toBe(200);
      expect((await fetch(`${base}/api/v1/exposures/summary`)).status).toBe(401);
      expect((await fetch(`${base}/api/v1/exposures/summary`, { headers: { 'x-api-key': 'dev-viewer' } })).status).toBe(200);
    } finally { await app.close(); }
  });
});
