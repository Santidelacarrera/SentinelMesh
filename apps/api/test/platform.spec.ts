import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { boot, Env, PW } from './helpers';
import { sha256 } from '../src/common/ids';

let t: Env;
const adm = () => t.as('admin-key');
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });
const seed = async () => {
  const web = (await t.analyst.post('/api/v1/inventory/assets', { type: 'web_app', identifier: 'shop', criticality: 'critical', internetFacing: true })).body;
  await t.analyst.post('/api/v1/intel/import', { kind: 'kev', payload: { vulnerabilities: [{ cveID: 'CVE-2024-7777', dueDate: '2030-01-01' }] } });
  const v = (await t.analyst.post('/api/v1/vulns', { assetId: web.id, cve: 'CVE-2024-7777', title: 'RCE in checkout', severity: 'critical', confidence: 'confirmed', source: 'dast', evidence: ['PoC returned id=0'] })).body;
  const c = (await t.analyst.post('/api/v1/cases', { name: 'Checkout compromise', description: 'tokens: password=hunter2hunter2', severity: 'critical', assetIds: [web.id], vulnerabilityIds: [v.id] })).body;
  await t.analyst.post(`/api/v1/cases/${c.id}/evidence`, { name: 'access.log', type: 'log', source: 'shop', content: 'GET /checkout?cmd=id' });
  await t.analyst.post('/api/v1/iam/identities', { kind: 'human', name: 'Root Ann', provider: 'entra', externalId: 'a', entitlements: ['Global Administrator'], mfaEnabled: false, lastActivityAt: new Date().toISOString() });
  return { web, v, c };
};
/** pdfkit writes uncompressed text as hex strings inside TJ arrays (split at kerning pairs): decode and join them. */
const pdfPlain = (b: Buffer) => [...b.toString('latin1').matchAll(/\[([^\]]*)\]\s*TJ/g)].map((m) => [...m[1].matchAll(/<([0-9a-fA-F]+)>/g)].map((h) => Buffer.from(h[1], 'hex').toString('latin1')).join('')).join(' | ');
const pdfHas = (b: Buffer, s: string) => pdfPlain(b).includes(s);

describe('executive dashboard', () => {
  it('says "no data" instead of inventing a score, then shows a transparent score with real counts', async () => {
    const e = (await t.viewer.get('/api/v1/dashboard/executive').expect(200)).body;
    expect(e).toMatchObject({ hasData: false, risk: { score: null, level: 'no data' }, assets: { total: 0 } }); expect(e.integrations.connectors.total).toBe(0); expect(e.trend.series.every((p: any) => p.vulnerabilities + p.cases + p.signals === 0)).toBe(true);
    await seed(); const d = (await t.viewer.get('/api/v1/dashboard/executive').expect(200)).body;
    expect(d.hasData).toBe(true); expect(d.risk.score).toBeGreaterThan(40); expect(d.risk.factors.reduce((s: number, f: any) => s + f.points, 0)).toBe(d.risk.score);
    expect(d).toMatchObject({ assets: { total: 1, internetFacing: 1 }, vulnerabilities: { open: 1, kev: 1, immediate: 1 }, cases: { active: 1 }, identities: { privileged: 1 } }); expect(d.priorities[0].explanation).toMatch(/KEV/);
    expect(d.trend.series.at(-1)).toMatchObject({ vulnerabilities: 1, cases: 1 }); expect(d.limitations.length).toBeGreaterThan(0);
    expect((await t.other.get('/api/v1/dashboard/executive')).body).toMatchObject({ hasData: false });                   // other tenant sees nothing of ours
  });
  it('reports connector states as they really are', async () => {
    const platform = { userId: 'p', orgId: 'org_platform', role: 'platform_admin' as const, email: '' };
    await t.acc.createOrg(platform, { id: 'org_z', name: 'z', plan: 'enterprise', adminEmail: 'a@z.test', adminPassword: PW });
    const tok = (await t.http.post('/api/v1/auth/login').send({ org: 'org_z', email: 'a@z.test', password: PW })).body.accessToken, H = { Authorization: `Bearer ${tok}` };
    await t.http.post('/api/v1/connectors').set(H).send({ kind: 'wazuh', name: 'W', baseUrl: 'https://wazuh.example.test' }).expect(201);
    const d = (await t.http.get('/api/v1/dashboard/executive').set(H)).body; expect(d.integrations.connectors.byStatus).toEqual({ not_configured: 1 });
  });
});

describe('PDF reports', () => {
  it('generates the four report kinds with organisation, date, period, limitations and the real figures; hash is recorded and verified on download', async () => {
    const { c } = await seed();
    for (const [kind, expected] of [['executive', 'Executive security report'], ['technical', 'Technical vulnerability report'], ['identity', 'Identity & access report'], ['incident', 'Incident report']] as const) {
      const r = (await t.analyst.post('/api/v1/reports', { kind, caseId: kind === 'incident' ? c.id : undefined }).expect(201)).body;
      expect(r).toMatchObject({ kind, size: expect.any(Number) }); expect(r.objectKey).toBeUndefined();
      const pdf = await t.viewer.get(`/api/v1/reports/${r.id}/pdf`).buffer(true).parse((res, cb) => { const ch: Buffer[] = []; res.on('data', (x: Buffer) => ch.push(x)); res.on('end', () => cb(null, Buffer.concat(ch))); }).expect(200);
      const buf = pdf.body as Buffer;
      expect(buf.subarray(0, 5).toString()).toBe('%PDF-'); expect(sha256(buf)).toBe(r.sha256); expect(pdf.headers['content-type']).toMatch(/application\/pdf/);
      for (const s of [expected, 'org_acme', 'Limitations of the data', 'Generated by', 'Period analysed']) expect(pdfHas(buf, s)).toBe(true);
      if (kind === 'technical') for (const s of ['CVE-2024-7777', 'shop']) expect(pdfHas(buf, s)).toBe(true);
      if (kind === 'incident') { for (const s of ['Checkout compromise', 'access.log', 'Timeline']) expect(pdfHas(buf, s)).toBe(true); expect(pdfHas(buf, 'hunter2hunter2')).toBe(false); }       // secrets never reach the PDF
      if (kind === 'identity') for (const s of ['Root Ann', 'privileged_no_mfa']) expect(pdfHas(buf, s)).toBe(true);
    }
    expect((await t.audit.list('org_acme')).map((e) => e.event)).toEqual(expect.arrayContaining(['report.generated', 'report.downloaded']));
    expect((await t.viewer.get('/api/v1/reports')).body).toHaveLength(4);
  });
  it('does not invent figures when there is no data, and refuses bad parameters', async () => {
    const r = (await t.analyst.post('/api/v1/reports', { kind: 'executive' }).expect(201)).body;
    const buf = (await t.viewer.get(`/api/v1/reports/${r.id}/pdf`).buffer(true).parse((res, cb) => { const ch: Buffer[] = []; res.on('data', (x: Buffer) => ch.push(x)); res.on('end', () => cb(null, Buffer.concat(ch))); })).body as Buffer;
    expect(pdfHas(buf, 'No data has been ingested yet')).toBe(true); expect(pdfHas(buf, 'Global risk:')).toBe(false);
    await t.analyst.post('/api/v1/reports', { kind: 'incident' }).expect(400); await t.analyst.post('/api/v1/reports', { kind: 'incident', caseId: 'case_nope' }).expect(404);
    await t.analyst.post('/api/v1/reports', { kind: 'executive', from: '2026-02-01T00:00:00Z', to: '2026-01-01T00:00:00Z' }).expect(400); await t.analyst.post('/api/v1/reports', { kind: 'secret' }).expect(400);
  });
  it('is permissioned, tamper-evident and tenant isolated', async () => {
    const r = (await t.analyst.post('/api/v1/reports', { kind: 'technical' }).expect(201)).body;
    await t.viewer.post('/api/v1/reports', { kind: 'technical' }).expect(403); await t.other.get(`/api/v1/reports/${r.id}/pdf`).expect(404); expect((await t.other.get('/api/v1/reports')).body).toEqual([]);
    const row = await t.db.reports.get('org_acme', r.id); await t.storage.put(row!.objectKey, '%PDF-1.4 forged'); await t.viewer.get(`/api/v1/reports/${r.id}/pdf`).expect(400);
  });
});

describe('AI assistant', () => {
  it('explains from stored records only: sources, confidence, assumptions, limitations, and never executes anything', async () => {
    const { v, c } = await seed();
    const e = (await t.analyst.post('/api/v1/ai/explain', { kind: 'vulnerability', id: v.id }).expect(200)).body;
    expect(e).toMatchObject({ kind: 'vulnerability', executed: [], confidence: { level: 'high', value: 1 } }); expect(e.sources).toEqual(expect.arrayContaining([{ type: 'vulnerability', id: v.id }]));
    expect(e.details.join(' ')).toMatch(/KEV/); expect(e.assumptions.length).toBeGreaterThan(0); expect(e.limitations.join(' ')).toMatch(/No EPSS/); expect(e.recommendations.join(' ')).toMatch(/Remediate/);
    const ce = (await t.analyst.post('/api/v1/ai/explain', { kind: 'case', id: c.id }).expect(200)).body; expect(ce.sources.map((s: any) => s.type)).toEqual(expect.arrayContaining(['case', 'asset', 'evidence'])); expect(ce.confidence.basis).toMatch(/no automated correlation/);
    expect((await t.analyst.post('/api/v1/ai/explain', { kind: 'priorities' }).expect(200)).body.sources).toHaveLength(1);
    await t.analyst.post('/api/v1/ai/explain', { kind: 'vulnerability', id: 'vul_missing' }).expect(404); await t.analyst.post('/api/v1/ai/explain', { kind: 'vulnerability' }).expect(400); await t.analyst.post('/api/v1/ai/explain', { kind: 'case', id: c.id, extra: 1 }).expect(400);
    await t.other.post('/api/v1/ai/explain', { kind: 'vulnerability', id: v.id }).expect(404);
    expect((await t.audit.list('org_acme')).some((a) => a.event === 'ai.explained')).toBe(true);
  });
  it('explains an attack path as theoretical, with its assumptions', async () => {
    const { web } = await seed(); const db = (await t.analyst.post('/api/v1/inventory/assets', { type: 'database', identifier: 'ledger', criticality: 'critical' })).body;
    await t.analyst.post('/api/v1/inventory/relations', { from: web.id, to: db.id, kind: 'depends_on' });
    const p = (await t.viewer.get('/api/v1/ctem/attack-paths')).body[0]; const e = (await t.analyst.post('/api/v1/ai/explain', { kind: 'attack_path', id: p.id }).expect(200)).body;
    expect(e.limitations.join(' ')).toMatch(/NOT an intrusion/); expect(e.summary).toMatch(/Theoretical path/);
  });
  describe('external language model (opt-in)', () => {
    let llm: Server, seen: string[]; const prev = { ...process.env };
    beforeEach(async () => {
      seen = []; llm = createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { seen.push(b); res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ text: 'Plain-language summary. Contact <EMAIL> token=abcdef123456' })); }); });
      await new Promise<void>((r) => llm.listen(0, '127.0.0.1', r)); process.env.AI_LLM_URL = `http://127.0.0.1:${(llm.address() as AddressInfo).port}/v1`; process.env.AI_ALLOW_HTTP = '1'; process.env.AI_PRIVATE_HOSTS = '["127.0.0.1"]';
    });
    afterEach(async () => { await new Promise((r) => llm.close(r)); process.env = { ...prev }; });
    it('needs operator configuration AND administrator consent, pseudonymises what it sends, labels the result and logs no content', async () => {
      const { v } = await seed();
      await t.analyst.post('/api/v1/ai/explain', { kind: 'vulnerability', id: v.id, external: true }).expect(403);       // no consent yet
      await t.analyst.post('/api/v1/ai/settings', { enabled: true }).expect(403);
      expect((await adm().post('/api/v1/ai/settings', { enabled: true }).expect(200)).body).toMatchObject({ externalEnabled: true, providerConfigured: true });
      await t.db.vulns.update('org_acme', v.id, { description: 'Contact ops@acme.test from 203.0.113.9 using api_key=sk_live_ABCDEFGHIJKLMNOP1234' });
      const e = (await t.analyst.post('/api/v1/ai/explain', { kind: 'vulnerability', id: v.id, external: true }).expect(200)).body;
      expect(e.externalNarrative.notice).toMatch(/Verify against the sources/); expect(e.externalNarrative.text).not.toContain('abcdef123456'); expect(e.summary).toBeTruthy(); expect(e.executed).toEqual([]);
      expect(seen).toHaveLength(1); expect(seen[0]).not.toMatch(/ops@acme\.test|203\.0\.113\.9|sk_live_ABCDEFGHIJKLMNOP1234/); expect(seen[0]).toMatch(/<EMAIL>|<IP>/);
      const call = (await t.audit.list('org_acme')).find((a) => a.event === 'ai.external_call')!; expect(JSON.stringify(call.data)).not.toMatch(/acme|203\.0\.113/); expect(JSON.stringify(await t.audit.list('org_acme'))).toContain('ai.external_consent_granted');
      await adm().post('/api/v1/ai/settings', { enabled: false }).expect(200); await t.analyst.post('/api/v1/ai/explain', { kind: 'vulnerability', id: v.id, external: true }).expect(403);
    });
    it('consent cannot be granted when the operator did not configure a provider', async () => { delete process.env.AI_LLM_URL; await adm().post('/api/v1/ai/settings', { enabled: true }).expect(400); });
  });
});

describe('privacy tooling', () => {
  it('exports the organisation data without any secret, and records the export', async () => {
    await seed(); await t.acc.createUser({ userId: 'p', orgId: 'org_platform', role: 'platform_admin', email: '' }, 'org_acme', { email: 'u@acme.test', password: PW, role: 'viewer', customRoles: [] });
    await adm().post('/api/v1/connectors', { kind: 'wazuh', name: 'W', baseUrl: 'https://w.example.test', credentials: { username: 'u', password: 'pw-secret-1' } });
    await t.analyst.get('/api/v1/privacy/export').expect(403);
    const x = (await adm().get('/api/v1/privacy/export').expect(200)).body, dump = JSON.stringify(x);
    expect(x.data.users[0].email).toBe('u@acme.test'); expect(x.data.assets).toHaveLength(1); expect(x.data.vulnerabilities).toHaveLength(1); expect(x.data.audit.length).toBeGreaterThan(3);
    for (const secret of ['scrypt$', 'passwordHash', 'credentialsEnc', 'pw-secret-1', 'objectKey', 'v1:']) expect(dump).not.toContain(secret);
    expect((await t.audit.list('org_acme')).some((a) => a.event === 'privacy.export')).toBe(true);
    expect((await t.other.get('/api/v1/privacy/export')).status).toBe(403);
  });
  it('applies configurable retention to transient data only and keeps what backs a case, the audit trail and evidence', async () => {
    const { c } = await seed(); const old = new Date(Date.now() - 400 * 86400000).toISOString();
    const mk = async (id: string, extra: object = {}) => t.db.signals.put({ id, orgId: 'org_acme', source: 's', sourceId: id, dedupKey: id, kind: 'alert', title: id, severity: 'low', at: old, cves: [], domains: [], ips: [], createdAt: old, ...extra } as any);
    await mk('sig_old'); await mk('sig_case'); await mk('sig_new', { createdAt: new Date().toISOString() });
    await t.db.cases.update('org_acme', c.id, { signalIds: ['sig_case'] });
    await adm().post('/api/v1/privacy/retention', { signalsDays: 5 }).expect(400); expect((await adm().post('/api/v1/privacy/retention', { signalsDays: 90 }).expect(200)).body).toMatchObject({ signalsDays: 90, notificationsDays: 180 });
    const r = (await adm().post('/api/v1/privacy/retention/apply').expect(200)).body;
    expect(r.removed.signals).toBe(1); expect((await t.db.signals.list('org_acme')).map((s) => s.id).sort()).toEqual(['sig_case', 'sig_new']);
    expect(await t.db.evidence.list('org_acme')).toHaveLength(1); expect((await t.audit.verify('org_acme')).ok).toBe(true);
  });
  it('erases a user only with the exact confirmation, never yourself or the last admin, and kills their sessions', async () => {
    const platform = { userId: 'p', orgId: 'org_platform', role: 'platform_admin' as const, email: '' };
    const u = await t.acc.createUser(platform, 'org_acme', { email: 'leaver@acme.test', password: PW, role: 'analyst', customRoles: [] });
    const tok = (await t.http.post('/api/v1/auth/login').send({ org: 'org_acme', email: 'leaver@acme.test', password: PW }).expect(200)).body.accessToken;
    await adm().post('/api/v1/privacy/erase-user', { userId: u.id, confirm: 'yes please' }).expect(400);
    await adm().post('/api/v1/privacy/erase-user', { userId: u.id, confirm: 'ERASE leaver@acme.test' }).expect(200);
    await t.http.get('/api/v1/me').set('Authorization', `Bearer ${tok}`).expect(401);
    const gone = await t.db.users.get('org_acme', u.id); expect(gone).toMatchObject({ status: 'disabled' }); expect(gone!.email).toMatch(/^erased-.*@invalid\.invalid$/);
    expect((await t.audit.list('org_acme')).some((a) => a.event === 'privacy.user_erased')).toBe(true);
    await adm().post('/api/v1/privacy/erase-user', { userId: 'usr_nope', confirm: 'ERASE x' }).expect(404);
    await t.db.orgs.put({ id: 'org_acme', orgId: 'org_platform', name: 'a', plan: 'business', status: 'active', retentionDays: 365, createdAt: '', createdBy: 'x' }); await adm().get('/api/v1/privacy/export').expect(402);
  });
});

describe('observability', () => {
  it('exposes Prometheus metrics (token-protected when configured) and readiness', async () => {
    await t.viewer.get('/api/v1/exposures/summary'); await t.http.get('/api/v1/me').expect(401);
    const m = (await t.http.get('/metrics').expect(200)).text;
    expect(m).toContain('sentinel_http_requests_total{method="GET",status="2xx"}'); expect(m).toContain('sentinel_http_requests_total{method="GET",status="4xx"}'); expect(m).toMatch(/sentinel_http_request_duration_seconds_bucket\{.*le="\+Inf"\}/); expect(m).toContain('sentinel_queue_waiting 0'); expect(m).toContain('sentinel_uptime_seconds');
    expect(m).not.toMatch(/org_acme|dev-viewer/);                                                       // no tenant data or credentials in labels
    process.env.METRICS_TOKEN = 'scrape-token-123456'; await t.http.get('/metrics').expect(403); await t.http.get('/metrics').set('Authorization', 'Bearer scrape-token-123456').expect(200); delete process.env.METRICS_TOKEN;
    expect((await t.http.get('/readyz').expect(200)).body).toMatchObject({ ready: true, checks: { database: 'memory' } });
  });
  it('the operations health view finds failed connectors, stuck work and failed notifications from real records', async () => {
    expect((await adm().get('/api/v1/ops/health').expect(200)).body).toMatchObject({ status: 'ok', issues: [] });
    await t.db.connectors.put({ id: 'con_x', orgId: 'org_acme', kind: 'wazuh', name: 'Wazuh', enabled: true, baseUrl: 'https://w.test', options: {}, permissions: [], status: 'error', lastError: 'HTTP 401', createdAt: '', activity: [] });
    await t.db.runs.put({ id: 'run_x', orgId: 'org_acme', playbookId: 'p', playbookKey: 'k', playbookVersion: 1, mode: 'ASSISTED', effectiveMode: 'ASSISTED', trigger: { type: 'signal', refId: 's' }, dedupKey: 'k', requestedBy: 'system', evidence: [], steps: [], status: 'executing', createdAt: '', updatedAt: new Date(Date.now() - 3 * 3600_000).toISOString(), history: [] });
    const h = (await adm().get('/api/v1/ops/health').expect(200)).body;
    expect(h.status).toBe('critical'); expect(h.issues.map((i: any) => i.area)).toEqual(expect.arrayContaining(['connector', 'tasks'])); expect(h.issues.find((i: any) => i.area === 'connector').detail).toMatch(/HTTP 401/);
    await t.analyst.get('/api/v1/ops/health').expect(403);
  });
  it('throttles credential endpoints per IP', async () => {
    process.env.AUTH_RATE_LIMIT_PER_MIN = '4'; const t2 = await boot();
    try { const codes: number[] = []; for (let i = 0; i < 7; i++) codes.push((await t2.http.post('/api/v1/auth/login').send({ org: 'org_acme', email: 'x@acme.test', password: 'whatever-pass-1' })).status); expect(codes.filter((c) => c === 429).length).toBeGreaterThanOrEqual(2); expect(codes[0]).toBe(401); }
    finally { delete process.env.AUTH_RATE_LIMIT_PER_MIN; await t2.queue.idle(); await t2.app.close(); }
  });
});
