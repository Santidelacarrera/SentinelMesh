import { createServer, IncomingMessage, Server, ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import { generateKeyPairSync } from 'node:crypto';
import { boot, Env, PW } from './helpers';
import { HttpClient, TokenBucket, TokenManager, ConnectorError } from '../src/connectors/http';
import { aws } from '../src/connectors/cloud';

/** Local servers that speak the documented wire protocol of each product. They prove OUR client code and normalisation; they are NOT the real services. */
type Handler = (req: IncomingMessage, body: string, res: ServerResponse) => boolean | void;
class Mock {
  server: Server; hits: Array<{ method: string; url: string; auth?: string; body: string }> = []; handlers: Handler[] = [];
  constructor() {
    this.server = createServer((req, res) => {
      let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => {
        this.hits.push({ method: req.method!, url: req.url!, auth: req.headers.authorization, body });
        for (const h of this.handlers) if (h(req, body, res) !== false && res.writableEnded) return;
        if (!res.writableEnded) { res.statusCode = 404; res.end('{"error":"no handler"}'); }
      });
    });
  }
  async start() { await new Promise<void>((r) => this.server.listen(0, '127.0.0.1', r)); return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`; }
  stop() { return new Promise((r) => this.server.close(r)); }
  json(res: ServerResponse, v: unknown, status = 200, headers: Record<string, string> = {}) { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(v)); return true; }
}

const ALERT_TS = new Date(Date.now() - 3600_000).toISOString();
let t: Env, mock: Mock, base: string, tokens = 0;
const sleepless = async () => undefined;
beforeAll(() => { process.env.CONNECTOR_ALLOW_HTTP = '1'; process.env.CONNECTOR_PRIVATE_HOSTS = '["127.0.0.1","localhost"]'; });
beforeEach(async () => { t = await boot(); mock = new Mock(); base = await mock.start(); tokens = 0; });
afterEach(async () => { await mock.stop(); await t.queue.idle(); await t.app.close(); });

async function adminToken() {
  const platform = { userId: 'p', orgId: 'org_platform', role: 'platform_admin' as const, email: '' };
  await t.acc.createOrg(platform, { id: 'org_c', name: 'c', plan: 'enterprise', adminEmail: 'a@c.test', adminPassword: PW });
  const r = await t.http.post('/api/v1/auth/login').send({ org: 'org_c', email: 'a@c.test', password: PW }).expect(200);
  const h = { get: (p: string) => t.http.get(p).set('Authorization', `Bearer ${r.body.accessToken}`), post: (p: string, b?: object) => t.http.post(p).set('Authorization', `Bearer ${r.body.accessToken}`).send(b ?? {}) };
  return h;
}

describe('HTTP transport', () => {
  it('retries 429/5xx with backoff and Retry-After, then gives up with a retriable error', async () => {
    let n = 0; mock.handlers.push((_r, _b, res) => (++n < 3 ? mock.json(res, {}, n === 1 ? 429 : 503, n === 1 ? { 'retry-after': '1' } : {}) : mock.json(res, { ok: true })));
    const waits: number[] = [], c = new HttpClient({ baseUrl: base, sleep: async (ms) => { waits.push(ms); }, retries: 3 });
    expect((await c.get('x')).body).toEqual({ ok: true }); expect(n).toBe(3); expect(waits).toContain(1000);
    n = -100; const fail = new HttpClient({ baseUrl: base, sleep: sleepless, retries: 2 });
    mock.handlers.length = 0; mock.handlers.push((_r, _b, res) => mock.json(res, {}, 500));
    await expect(fail.get('x')).rejects.toMatchObject({ retriable: true, status: 500 });
  });
  it('does not retry client errors, and never leaks secrets into error messages', async () => {
    mock.handlers.push((_r, _b, res) => mock.json(res, { error: 'bad secret hunter2-secret-value' }, 400));
    const c = new HttpClient({ baseUrl: base, sleep: sleepless, secrets: ['hunter2-secret-value'] });
    const e = (await c.get('x').catch((x) => x)) as ConnectorError;
    expect(e.status).toBe(400); expect(e.retriable).toBe(false); expect(e.message).not.toContain('hunter2'); expect(mock.hits).toHaveLength(1);
  });
  it('rate limits with a token bucket and renews an expired/rejected OAuth token exactly once', async () => {
    let clock = 0; const b = new TokenBucket(2, 2, () => clock);
    expect([b.take(), b.take(), b.take()]).toEqual([0, 0, 500]); clock = 1000; expect(b.take()).toBeGreaterThanOrEqual(0);
    let issued = 0; const tm = new TokenManager(async () => ({ token: `tok${++issued}`, expiresInSec: 3600 }));
    mock.handlers.push((req, _b, res) => (req.headers.authorization === 'Bearer tok2' ? mock.json(res, { ok: 1 }) : mock.json(res, {}, 401)));
    const c = new HttpClient({ baseUrl: base, sleep: sleepless }); c.tokenProvider = tm;
    expect((await c.get('x')).body).toEqual({ ok: 1 }); expect(issued).toBe(2);
    const [a1, a2] = await Promise.all([tm.get(), tm.get()]); expect(a1).toBe(a2); expect(issued).toBe(2);
  });
  it('applies the SSRF policy to every request (private hosts are blocked unless the operator allowed them)', async () => {
    const c = new HttpClient({ baseUrl: 'http://169.254.169.254', sleep: sleepless, policy: { allowHttp: true } });
    await expect(c.get('latest/meta-data')).rejects.toThrow(/private|reserved/);
    await expect(new HttpClient({ baseUrl: 'http://example.com', policy: {} }).get('x')).rejects.toThrow(/scheme/);
  });
});

describe('connector lifecycle (API)', () => {
  const wazuhMock = () => {
    mock.handlers.push((req, _b, res) => {
      if (req.url!.startsWith('/security/user/authenticate')) { tokens++; if (req.headers.authorization !== `Basic ${Buffer.from('wuser:wpass-secret').toString('base64')}`) return mock.json(res, {}, 401); res.writeHead(200, { 'content-type': 'text/plain' }); res.end('jwt-token-wazuh'); return true; }
      if (req.headers.authorization !== 'Bearer jwt-token-wazuh') return mock.json(res, { error: 'unauthorised' }, 401);
      if (req.url!.startsWith('/manager/info')) return mock.json(res, { data: { affected_items: [{ version: 'v4.9.0' }] } });
      if (req.url!.startsWith('/agents')) return mock.json(res, { data: { total_affected_items: 2, affected_items: [{ id: '001', name: 'WEB-01', ip: '10.0.0.5', os: { name: 'Ubuntu' }, status: 'active' }, { id: '002', name: 'db-01', status: 'disconnected' }] } });
      return false;
    });
  };
  it('not configured → configured → connected → error, with encrypted credentials never returned or logged', async () => {
    const admin = await adminToken(); wazuhMock();
    const c = (await admin.post('/api/v1/connectors', { kind: 'wazuh', name: 'Wazuh prod', baseUrl: base }).expect(201)).body;
    expect(c).toMatchObject({ status: 'not_configured', hasCredentials: false, verification: 'simulated' });
    await admin.post(`/api/v1/connectors/${c.id}/test`).expect(400);                                         // no credentials yet: no fake "connected"
    const up = (await admin.post(`/api/v1/connectors/${c.id}`, { credentials: { username: 'wuser', password: 'wpass-secret' } }).expect(200)).body;
    expect(up.status).toBe('configured'); expect(JSON.stringify(up)).not.toContain('wpass-secret');
    const stored = JSON.stringify(await t.db.connectors.list('org_c')); expect(stored).not.toContain('wpass-secret'); expect(stored).toContain('v1:');   // sealed with AES-GCM
    const ok = (await admin.post(`/api/v1/connectors/${c.id}/test`).expect(200)).body;
    expect(ok).toMatchObject({ ok: true }); expect(ok.connector.status).toBe('connected'); expect(ok.detail).toMatch(/4\.9/);
    await admin.post(`/api/v1/connectors/${c.id}`, { credentials: { username: 'wuser', password: 'WRONG-password-x' } }).expect(200);
    const bad = (await admin.post(`/api/v1/connectors/${c.id}/test`).expect(200)).body;
    expect(bad.ok).toBe(false); expect(bad.connector.status).toBe('error'); expect(bad.detail).not.toContain('WRONG-password-x');
    const audit = JSON.stringify(await t.audit.list('org_c')); expect(audit).not.toContain('wpass-secret'); expect(audit).toContain('connector.tested');
  });
  it('syncs Wazuh agents into the inventory, ingests indexer alerts once, correlates assets and uses the cursor', async () => {
    const admin = await adminToken(); wazuhMock();
    mock.handlers.unshift((req, body, res) => {
      if (req.url!.startsWith('/wazuh-alerts-')) { const since = JSON.stringify(JSON.parse(body).query); return mock.json(res, { hits: { hits: since.includes(ALERT_TS) ? [] : [{ _id: 'al1', _source: { timestamp: ALERT_TS, rule: { id: '5710', level: 12, description: 'sshd: brute force' }, agent: { name: 'web-01', ip: '10.0.0.5' }, data: { srcip: '203.0.113.9', vulnerability: { cve: 'CVE-2024-3094' } } } }] } }); }
      if (req.url!.startsWith('/wazuh-states-vulnerabilities-')) return mock.json(res, { hits: { hits: [{ _source: { agent: { name: 'web-01' }, vulnerability: { id: 'CVE-2024-3094', severity: 'Critical', score: { base: 10 } }, package: { name: 'xz-utils', version: '5.6.0' } } }] } });
      return false;
    });
    const c = (await admin.post('/api/v1/connectors', { kind: 'wazuh', name: 'W', baseUrl: base, credentials: { username: 'wuser', password: 'wpass-secret' }, options: { indexerUrl: base } }).expect(201)).body;
    const r1 = (await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(200)).body;
    expect(r1.counts).toMatchObject({ assets: 2, signals: 1, vulns: 1, failed: 0 });
    expect(r1.connector).toMatchObject({ status: 'connected', cursor: ALERT_TS }); expect(r1.connector.lastSyncAt).toBeTruthy();
    const assets = (await admin.get('/api/v1/inventory/assets').expect(200)).body;
    expect(assets.items.map((a: any) => a.identifier).sort()).toEqual(['db-01', 'web-01']);
    const sig = (await admin.get('/api/v1/signals').expect(200)).body.items[0];
    expect(sig).toMatchObject({ source: 'wazuh', severity: 'critical', assetId: assets.items.find((a: any) => a.identifier === 'web-01').id, cves: ['CVE-2024-3094'] });
    const v = (await admin.get('/api/v1/vulns').expect(200)).body.items[0];
    expect(v).toMatchObject({ cve: 'CVE-2024-3094', confidence: 'suspected', source: 'connector:wazuh' });            // a scanner said so: not "confirmed"
    const r2 = (await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(200)).body;
    expect(r2.counts.signals).toBe(0);                                                                                // cursor + dedup: no duplicates
    expect(tokens).toBe(1);                                                                                           // one JWT reused across calls
    const d = (await admin.get(`/api/v1/connectors/${c.id}`).expect(200)).body; expect(d.runs).toHaveLength(2); expect(d.connector.activity[0].text).toMatch(/sync OK/);
  });
  it('failed syncs are reported as errors with a redacted message and can be disabled/enabled', async () => {
    const admin = await adminToken(); mock.handlers.push((_r, _b, res) => mock.json(res, { error: 'boom token=abc123456789' }, 400));
    const c = (await admin.post('/api/v1/connectors', { kind: 'wazuh', name: 'W', baseUrl: base, credentials: { username: 'u', password: 'p-secret-1' } }).expect(201)).body;
    const e = await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(502);
    expect(e.body.connector.status).toBe('error'); expect(JSON.stringify(e.body)).not.toContain('abc123456789');
    expect((await admin.get('/api/v1/connectors/health').expect(200)).body).toMatchObject({ total: 1, byStatus: { error: 1 } });
    expect((await admin.post(`/api/v1/connectors/${c.id}/disable`).expect(200)).body.status).toBe('disabled');
    await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(409);
    expect((await admin.post(`/api/v1/connectors/${c.id}/enable`).expect(200)).body.enabled).toBe(true);
  });
  it('CrowdStrike: OAuth2 client credentials, devices and alerts v2 normalised to assets and signals', async () => {
    const admin = await adminToken();
    mock.handlers.push((req, body, res) => {
      if (req.url === '/oauth2/token') { tokens++; return new URLSearchParams(body).get('client_secret') === 'cs-secret-xyz' ? mock.json(res, { access_token: 'cs-token', expires_in: 1799 }, 201) : mock.json(res, {}, 401); }
      if (req.headers.authorization !== 'Bearer cs-token') return mock.json(res, {}, 401);
      if (req.url!.startsWith('/devices/queries/devices/v1')) return mock.json(res, { resources: ['d1'], meta: { pagination: { total: 1 } } });
      if (req.url!.startsWith('/devices/entities/devices/v2')) return mock.json(res, { resources: [{ device_id: 'd1', hostname: 'LAPTOP-7', platform_name: 'Windows', status: 'normal' }] });
      if (req.url!.startsWith('/alerts/queries/alerts/v2')) return mock.json(res, { resources: ['c1'] });
      if (req.url!.startsWith('/alerts/entities/alerts/v2')) return mock.json(res, { resources: [{ composite_id: 'c1', name: 'Credential dumping', severity: 85, created_timestamp: '2026-02-01T00:00:00Z', device: { hostname: 'LAPTOP-7', local_ip: '10.1.1.7' }, user_name: 'jdoe', tactic: 'Credential Access' }] });
      return false;
    });
    const c = (await admin.post('/api/v1/connectors', { kind: 'crowdstrike', name: 'Falcon', baseUrl: base, credentials: { client_id: 'cid', client_secret: 'cs-secret-xyz' } }).expect(201)).body;
    expect((await admin.post(`/api/v1/connectors/${c.id}/test`).expect(200)).body.ok).toBe(true);
    expect((await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(200)).body.counts).toMatchObject({ assets: 1, signals: 1 });
    const s = (await admin.get('/api/v1/signals')).body.items[0]; expect(s).toMatchObject({ source: 'crowdstrike', severity: 'high', title: 'Credential dumping', user: 'jdoe' });
    expect(tokens).toBe(1);
  });
  it('Defender: separate tokens for Graph and the Defender for Endpoint API; alerts, machines and vulnerabilities', async () => {
    const admin = await adminToken(); const audiences: string[] = [];
    mock.handlers.push((req, body, res) => {
      if (req.url!.endsWith('/oauth2/v2.0/token')) { const sc = new URLSearchParams(body).get('scope')!; audiences.push(sc); return mock.json(res, { access_token: sc.includes('graph') ? 'g-tok' : 'm-tok', expires_in: 3599 }); }
      const tok = req.headers.authorization;
      if (req.url!.startsWith('/v1.0/security/alerts_v2')) return tok === 'Bearer g-tok' ? mock.json(res, { value: [{ id: 'a1', title: 'Suspicious PowerShell', severity: 'high', createdDateTime: '2026-03-01T00:00:00Z', evidence: [{ '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: 'ws-1.corp.test' }, { '@odata.type': '#microsoft.graph.security.userEvidence', userAccount: { accountName: 'asmith' } }] }] }) : mock.json(res, {}, 401);
      if (req.url!.startsWith('/api/machines')) return tok === 'Bearer m-tok' ? mock.json(res, { value: [{ id: 'm1', computerDnsName: 'ws-1.corp.test', osPlatform: 'Windows11', healthStatus: 'Active' }] }) : mock.json(res, {}, 401);
      if (req.url!.startsWith('/api/vulnerabilities/machinesVulnerabilities')) return tok === 'Bearer m-tok' ? mock.json(res, { value: [{ cveId: 'CVE-2024-21412', fqdn: 'ws-1.corp.test', severity: 'High', productName: 'windows_11' }] }) : mock.json(res, {}, 401);
      return false;
    });
    const c = (await admin.post('/api/v1/connectors', { kind: 'defender', name: 'MDE', baseUrl: base, options: { loginBase: base, graphBase: base, mdeBase: base.replace('127.0.0.1', 'localhost') }, credentials: { tenant_id: 'tid', client_id: 'cid', client_secret: 'ms-secret-1' } }).expect(201)).body;
    const r = (await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(200)).body;
    expect(r.counts).toMatchObject({ assets: 1, signals: 1, vulns: 1 }); expect(audiences.sort()).toEqual(['https://api.securitycenter.microsoft.com/.default', 'https://graph.microsoft.com/.default']);
    expect((await admin.get('/api/v1/signals')).body.items[0]).toMatchObject({ source: 'defender', host: 'ws-1', user: 'asmith', severity: 'high' });
  });
  it('Entra / Okta / Google Workspace: identities with MFA, roles, activity and privilege detection', async () => {
    const admin = await adminToken();
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    mock.handlers.push((req, body, res) => {
      const u = req.url!;
      if (u.endsWith('/oauth2/v2.0/token')) return mock.json(res, { access_token: 'ent-tok', expires_in: 3599 });
      if (u === '/token') return new URLSearchParams(body).get('assertion')?.split('.').length === 3 ? mock.json(res, { access_token: 'g-tok', expires_in: 3599 }) : mock.json(res, {}, 400);
      if (u.startsWith('/v1.0/directoryRoles') && !u.includes('/members')) return req.headers.authorization === 'Bearer ent-tok' ? mock.json(res, { value: [{ id: 'r1', displayName: 'Global Administrator' }] }) : mock.json(res, {}, 401);
      if (u.includes('/members')) return mock.json(res, { value: [{ id: 'u1' }] });
      if (u.startsWith('/v1.0/reports/authenticationMethods')) return mock.json(res, { value: [{ id: 'u1', isMfaRegistered: false }, { id: 'u2', isMfaRegistered: true }] });
      if (u.startsWith('/v1.0/users')) return mock.json(res, { value: [{ id: 'u1', displayName: 'Root Ann', userPrincipalName: 'ann@corp.test', accountEnabled: true, signInActivity: { lastSuccessfulSignInDateTime: '2024-01-01T00:00:00Z' } }, { id: 'u2', displayName: 'Bob', userPrincipalName: 'bob@corp.test', accountEnabled: false }] });
      if (u.startsWith('/api/v1/users/') && u.endsWith('/factors')) return mock.json(res, [{ status: 'ACTIVE' }]);
      if (u.startsWith('/api/v1/users/') && u.endsWith('/roles')) return mock.json(res, [{ type: 'SUPER_ADMIN' }]);
      if (u.startsWith('/api/v1/users')) return req.headers.authorization === 'SSWS okta-token-123' ? mock.json(res, [{ id: 'o1', status: 'ACTIVE', lastLogin: '2026-04-01T00:00:00Z', profile: { login: 'oli@corp.test', email: 'oli@corp.test', displayName: 'Oli' } }]) : mock.json(res, {}, 401);
      if (u.startsWith('/admin/directory/v1/users')) return req.headers.authorization === 'Bearer g-tok' ? mock.json(res, { users: [{ id: 'g1', primaryEmail: 'gus@corp.test', name: { fullName: 'Gus' }, isAdmin: true, isEnrolledIn2Sv: false, suspended: false, lastLoginTime: '2026-05-01T00:00:00Z' }, { id: 'g2', primaryEmail: 'new@corp.test', isAdmin: false, isEnrolledIn2Sv: true, lastLoginTime: '1970-01-01T00:00:00.000Z' }] }) : mock.json(res, {}, 401);
      return false;
    });
    const mk = async (body: object) => { const c = (await admin.post('/api/v1/connectors', body).expect(201)).body; return (await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(200)).body; };
    expect((await mk({ kind: 'entra', name: 'E', baseUrl: base, options: { loginBase: base }, credentials: { tenant_id: 't', client_id: 'c', client_secret: 'entra-secret-1' } })).counts.identities).toBe(2);
    expect((await mk({ kind: 'okta', name: 'O', baseUrl: base, credentials: { api_token: 'okta-token-123' } })).counts.identities).toBe(1);
    expect((await mk({ kind: 'google_workspace', name: 'G', baseUrl: base, options: { tokenUri: `${base}/token` }, credentials: { client_email: 'sa@p.iam.test', private_key: privateKey, subject: 'admin@corp.test' } })).counts.identities).toBe(2);
    const ids = (await admin.get('/api/v1/iam/identities?limit=50')).body.items as any[], by = (n: string) => ids.find((i) => i.name === n);
    expect(by('Root Ann')).toMatchObject({ provider: 'entra', privileged: true, mfaEnabled: false, status: 'active' }); expect(by('Bob').status).toBe('disabled');
    expect(by('Oli')).toMatchObject({ provider: 'okta', privileged: true, mfaEnabled: true }); expect(by('Gus')).toMatchObject({ provider: 'google_workspace', privileged: true, mfaEnabled: false });
    const risks = (await admin.get('/api/v1/iam/risks')).body as any[];
    expect(risks.some((r) => r.code === 'privileged_no_mfa' && r.severity === 'critical')).toBe(true);
    expect(risks.some((r) => r.code === 'inactive' && r.identityId === by('Root Ann').id)).toBe(true);
  });
  it('AWS connector normalises EC2, S3 and IAM through the SDK reader port (SDK itself is exercised only against an emulator in CI)', async () => {
    const admin = await adminToken(); const orig = aws.reader;
    aws.reader = () => ({ caller: async () => 'fake', instances: async () => [{ id: 'i-1', name: 'web', publicIp: '198.51.100.7', state: 'running', tags: ['Env=prod'] }, { id: 'i-2', state: 'terminated', tags: [] }], buckets: async () => [{ name: 'logs', public: false }, { name: 'site', public: true }],
      users: async () => [{ name: 'deploy', arn: 'arn:aws:iam::1:user/deploy', mfa: false, keyAgeDays: 400, policies: ['AdministratorAccess'], passwordLastUsed: new Date('2024-01-01') }] });
    try {
      const c = (await admin.post('/api/v1/connectors', { kind: 'aws', name: 'AWS', baseUrl: '', credentials: { access_key_id: 'AKIAxxxx', secret_access_key: 'secret-key-1234567890' } }).expect(201)).body;
      expect((await admin.post(`/api/v1/connectors/${c.id}/test`).expect(200)).body.ok).toBe(true);
      expect((await admin.post(`/api/v1/connectors/${c.id}/sync`).expect(200)).body.counts).toMatchObject({ assets: 3, identities: 1 });
      const a = (await admin.get('/api/v1/inventory/assets?internetFacing=true')).body.items.map((x: any) => x.identifier).sort(); expect(a).toEqual(['i-1', 's3:site']);
      expect((await admin.get('/api/v1/iam/risks')).body.map((r: any) => r.code)).toEqual(expect.arrayContaining(['privileged_no_mfa', 'service_no_rotation']));
    } finally { aws.reader = orig; }
  });
  it('Active Directory is reported as not implemented (no fake connection); isolation, permissions and plan limits hold', async () => {
    const admin = await adminToken();
    expect((await admin.post('/api/v1/connectors', { kind: 'ad', name: 'AD', baseUrl: 'ldap://dc' }).expect(501)).body.reason).toMatch(/Entra Connect/);
    await admin.post('/api/v1/connectors', { kind: 'wazuh', name: 'bad', baseUrl: 'ftp://x' }).expect(400);
    await admin.post('/api/v1/connectors', { kind: 'wazuh', name: 'bad', baseUrl: base, credentials: { username: 'u' } }).expect(400);
    const c = (await admin.post('/api/v1/connectors', { kind: 'wazuh', name: 'ok', baseUrl: base }).expect(201)).body;
    await t.analyst.post('/api/v1/connectors', { kind: 'wazuh', name: 'x', baseUrl: base }).expect(403);                        // analysts cannot configure connectors
    await t.other.get(`/api/v1/connectors/${c.id}`).expect(404);
    expect((await t.other.get('/api/v1/connectors')).body).toEqual([]);
    await t.db.orgs.put({ id: 'org_acme', orgId: 'org_platform', name: 'a', plan: 'starter', status: 'active', retentionDays: 365, createdAt: '', createdBy: 'x' });
    await t.analyst.get('/api/v1/connectors').expect(402);
    expect((await admin.get('/api/v1/connectors/catalog')).body.find((x: any) => x.kind === 'ad')).toMatchObject({ implemented: false });
  });
});
