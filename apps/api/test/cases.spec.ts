import { boot, Env, PW } from './helpers';
import { CorrelationService } from '../src/cases/correlation.service';

let t: Env;
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });
const caseBody = (o: object = {}) => ({ name: 'Suspicious login', description: 'd', severity: 'high', ...o });
const sig = (o: object) => ({ source: 'crowdstrike', sourceId: Math.random().toString(36).slice(2), kind: 'detection', title: 'Credential dumping', severity: 'critical', at: new Date().toISOString(), ...o });
const asset = async (o: object = {}) => (await t.analyst.post('/api/v1/inventory/assets', { type: 'server', identifier: 'web-01', criticality: 'critical', internetFacing: true, ...o }).expect(201)).body;

describe('incident management', () => {
  it('opens numbered cases, enforces the workflow, requires notes to resolve/close, and keeps a chronological timeline', async () => {
    const a = (await t.analyst.post('/api/v1/cases', caseBody()).expect(201)).body, b = (await t.analyst.post('/api/v1/cases', caseBody({ name: 'second' })).expect(201)).body;
    expect([a.number, b.number]).toEqual([1, 2]); expect(a.status).toBe('new');
    await t.analyst.post(`/api/v1/cases/${a.id}/status`, { status: 'closed' }).expect(400);          // closing needs a note
    await t.analyst.post(`/api/v1/cases/${a.id}/status`, { status: 'remediating' }).expect(400);     // new → remediating is not allowed
    for (const s of ['investigating', 'contained', 'remediating']) await t.analyst.post(`/api/v1/cases/${a.id}/status`, { status: s }).expect(200);
    await t.analyst.post(`/api/v1/cases/${a.id}/status`, { status: 'resolved' }).expect(400);
    await t.analyst.post(`/api/v1/cases/${a.id}/status`, { status: 'resolved', note: 'patched and verified' }).expect(200);
    await t.analyst.post(`/api/v1/cases/${a.id}/status`, { status: 'closed', note: 'confirmed by owner' }).expect(200);
    await t.analyst.post(`/api/v1/cases/${a.id}/status`, { status: 'investigating' }).expect(400);   // closed is terminal
    const d = (await t.viewer.get(`/api/v1/cases/${a.id}`).expect(200)).body.case;
    expect(d.closedAt).toBeTruthy(); expect(d.timeline.map((x: any) => x.kind)).toEqual(['opened', 'status', 'status', 'status', 'status', 'status']);
    expect((await t.audit.list('org_acme')).filter((e) => e.event === 'case.status_changed')).toHaveLength(5);
  });
  it('comments, assignment, links, filters, validation and tenant isolation', async () => {
    const as = await asset(), c = (await t.analyst.post('/api/v1/cases', caseBody()).expect(201)).body;
    await t.analyst.post(`/api/v1/cases/${c.id}/comments`, { text: 'checked with token=abc123456789def' }).expect(201);
    expect(JSON.stringify((await t.viewer.get(`/api/v1/cases/${c.id}/timeline`)).body)).not.toContain('abc123456789def');     // secrets never reach the timeline
    await t.analyst.post(`/api/v1/cases/${c.id}/assign`, { assigneeId: 'u_ghost' }).expect(400);
    const platform = { userId: 'p', orgId: 'org_platform', role: 'platform_admin' as const, email: '' };
    const u = await t.acc.createUser({ ...platform, orgId: 'org_acme' }, 'org_acme', { email: 'z@acme.test', password: PW, role: 'analyst', customRoles: [] });
    await t.analyst.post(`/api/v1/cases/${c.id}/assign`, { assigneeId: u.id }).expect(200);
    await t.analyst.post(`/api/v1/cases/${c.id}/links`, { assetIds: ['ast_nope'] }).expect(400);
    expect((await t.analyst.post(`/api/v1/cases/${c.id}/links`, { assetIds: [as.id] }).expect(200)).body.assetIds).toEqual([as.id]);
    expect((await t.viewer.get(`/api/v1/cases?assignee=${u.id}&severity=high`)).body.total).toBe(1);
    await t.analyst.post('/api/v1/cases', { ...caseBody(), unknown: 1 }).expect(400);
    await t.viewer.post('/api/v1/cases', caseBody()).expect(403);
    await t.other.get(`/api/v1/cases/${c.id}`).expect(404); await t.other.post(`/api/v1/cases/${c.id}/comments`, { text: 'x' }).expect(404);
    expect((await t.other.get('/api/v1/cases')).body.total).toBe(0);
  });
});

describe('forensic evidence', () => {
  const mk = async () => { const c = (await t.analyst.post('/api/v1/cases', caseBody()).expect(201)).body; const e = (await t.analyst.post(`/api/v1/cases/${c.id}/evidence`, { name: 'auth.log', type: 'log', source: 'host-1', content: 'Nov 1 sshd[1]: Failed password for root\n' }).expect(201)).body; return { c, e }; };
  it('hashes at capture, keeps a custody trail for every access, and verifies integrity on read', async () => {
    const { c, e } = await mk();
    expect(e.sha256).toMatch(/^[0-9a-f]{64}$/); expect(e.custody[0]).toMatchObject({ action: 'captured', actor: 'u_analyst' }); expect(e.objectKey).toBeUndefined();
    await t.viewer.get(`/api/v1/evidence/${e.id}`).expect(200);
    const dl = await t.analyst.get(`/api/v1/evidence/${e.id}/content`).expect(200);
    expect(dl.headers['x-content-sha256']).toBe(e.sha256); expect(dl.body.toString()).toContain('Failed password');
    const after = (await t.viewer.get(`/api/v1/evidence/${e.id}`)).body;
    expect(after.custody.map((x: any) => x.action)).toEqual(expect.arrayContaining(['captured', 'viewed', 'integrity_verified', 'downloaded']));
    expect((await t.viewer.get(`/api/v1/cases/${c.id}`)).body.evidence[0].id).toBe(e.id);
    expect((await t.audit.list('org_acme')).map((x) => x.event)).toEqual(expect.arrayContaining(['evidence.captured', 'evidence.viewed', 'evidence.downloaded']));
    await t.viewer.get(`/api/v1/evidence/${e.id}/content`).expect(403);                              // viewers can read metadata, not export content
  });
  it('detects tampering of stored bytes, refuses to serve them and records the failure', async () => {
    const { e } = await mk();
    const row = await t.db.evidence.get('org_acme', e.id); await t.storage.put(row!.objectKey, 'forged log line');
    await t.analyst.get(`/api/v1/evidence/${e.id}/content`).expect(409);
    expect((await t.analyst.post(`/api/v1/evidence/${e.id}/verify`).expect(200)).body).toMatchObject({ intact: false });
    expect((await t.audit.list('org_acme')).some((x) => x.event === 'evidence.integrity_failure')).toBe(true);
    expect((await t.viewer.get(`/api/v1/evidence/${e.id}`)).body.custody.some((x: any) => x.detail === 'MISMATCH')).toBe(true);
  });
  it('metadata changes need a reason and keep before/after; hash and content are immutable; there is no delete', async () => {
    const { e } = await mk();
    await t.analyst.post(`/api/v1/evidence/${e.id}/metadata`, { metadata: { host: 'h2' }, reason: 'x' }).expect(400);
    const m = (await t.analyst.post(`/api/v1/evidence/${e.id}/metadata`, { metadata: { host: 'host-2' }, reason: 'correct hostname' }).expect(200)).body;
    expect(m.modifications[0]).toMatchObject({ before: {}, after: { host: 'host-2' } }); expect(m.sha256).toBe(e.sha256);
    await t.analyst.post(`/api/v1/evidence/${e.id}/metadata`, { metadata: {}, reason: 'try sha', sha256: 'x' }).expect(400);
    await t.analyst.post(`/api/v1/evidence/${e.id}`, {}).expect(404); expect((await t.http.delete(`/api/v1/evidence/${e.id}`).set('x-api-key', 'dev-approver')).status).toBe(404);
  });
  it('exports a verified bundle with manifest and custody, records it, and is tenant isolated', async () => {
    const { c, e } = await mk();
    await t.analyst.post(`/api/v1/cases/${c.id}/evidence/export`, { purpose: 'x' }).expect(400);
    const x = (await t.analyst.post(`/api/v1/cases/${c.id}/evidence/export`, { purpose: 'handover to legal counsel' }).expect(200)).body;
    expect(x.manifest.files[0]).toMatchObject({ id: e.id, sha256: e.sha256 }); expect(Buffer.from(x.files[0].contentBase64, 'base64').toString()).toContain('sshd');
    expect(x.files[0].custody.map((c2: any) => c2.action)).toContain('exported'); expect(x.notice).toMatch(/admissibility/);
    expect((await t.viewer.get(`/api/v1/cases/${c.id}/timeline`)).body.some((tl: any) => /exported/.test(tl.text))).toBe(true);
    await t.other.post(`/api/v1/cases/${c.id}/evidence/export`, { purpose: 'steal it all' }).expect(404); await t.other.get(`/api/v1/evidence/${e.id}`).expect(404); await t.other.get(`/api/v1/evidence/${e.id}/content`).expect(404);
    await t.analyst.post(`/api/v1/cases/${c.id}/evidence`, { name: 'x', source: 's', content: '' }).expect(400);
    await t.other.post(`/api/v1/cases/${c.id}/evidence`, { name: 'x', source: 's', content: 'planted' }).expect(404);
  });
});

describe('correlation', () => {
  it('combines independent reasons with a noisy-OR and ignores shared private IPs', () => {
    const a: any = { assetId: 'a1', identityId: 'i1', ips: ['10.0.0.1', '203.0.113.9'], domains: [], cves: [], source: 'x' }, b: any = { assetId: 'a1', identityId: 'i1', ips: ['10.0.0.1', '203.0.113.9'], domains: [], cves: [], source: 'y' };
    const r = CorrelationService.reasons(a, b); expect(r.map((x) => x.type).sort()).toEqual(['asset', 'identity', 'ip']); expect(r.find((x) => x.type === 'ip')!.value).toBe('203.0.113.9');
    expect(CorrelationService.combine(r)).toBeCloseTo(1 - 0.2 * 0.3 * 0.4, 3);
    expect(CorrelationService.reasons({ ...a, assetId: undefined, identityId: undefined, ips: ['192.168.1.5'] }, { ...b, assetId: undefined, identityId: undefined, ips: ['192.168.1.5'] })).toEqual([]);
  });
  it('correlates CrowdStrike + Wazuh + Defender on one asset, opens one case, stays "probable", and needs a human to confirm', async () => {
    const as = await asset({ identifier: 'web-01' });
    await t.analyst.post('/api/v1/vulns', { assetId: as.id, cve: 'CVE-2024-3094', title: 'xz backdoor', severity: 'critical', confidence: 'confirmed', source: 'edr' }).expect(201);
    await t.analyst.post('/api/v1/signals', { signals: [sig({ host: 'WEB-01', ip: '198.51.100.50', ips: ['203.0.113.9'] })] }).expect(201);
    expect((await t.viewer.get('/api/v1/correlations')).body).toHaveLength(0);                       // one signal alone is not a correlation
    await t.analyst.post('/api/v1/signals', { signals: [sig({ source: 'wazuh', kind: 'alert', title: 'sshd brute force', severity: 'high', host: 'web-01', ips: ['203.0.113.9'], cves: ['CVE-2024-3094'] })] }).expect(201);
    await t.analyst.post('/api/v1/signals', { signals: [sig({ source: 'defender', kind: 'alert', title: 'Suspicious process', severity: 'high', host: 'web-01' })] }).expect(201);
    const cors = (await t.viewer.get('/api/v1/correlations')).body; expect(cors).toHaveLength(1);
    const c = cors[0]; expect(c.status).toBe('probable'); expect(c.signalIds).toHaveLength(3); expect(c.assetId).toBe(as.id);
    expect(c.reasons.map((r: any) => r.type)).toEqual(expect.arrayContaining(['asset', 'ip', 'vulnerability', 'time'])); expect(c.reasons.find((r: any) => r.type === 'asset')).toMatchObject({ confidence: 0.8 });
    expect(c.confidence).toBeGreaterThan(0.9); expect(c.riskScore).toBeGreaterThanOrEqual(60); expect(c.vulnerabilityIds).toHaveLength(1); expect(c.recommendation.join(' ')).toMatch(/hypothesis/);
    const cases = (await t.viewer.get('/api/v1/cases')).body; expect(cases.total).toBe(1);
    const cd = (await t.viewer.get(`/api/v1/cases/${cases.items[0].id}`)).body;
    expect(cd.case).toMatchObject({ source: 'correlation', correlationId: c.id }); expect(cd.signals).toHaveLength(3); expect(cd.vulnerabilities).toHaveLength(1); expect(cd.case.description).toMatch(/probable, not confirmed/);
    const dup = (await t.analyst.post('/api/v1/signals', { signals: [{ ...sig({ host: 'web-01' }), source: 'wazuh', sourceId: cd.signals[1].sourceId }] }).expect(201)).body;
    expect(dup).toMatchObject({ duplicates: expect.any(Number) });
    await t.viewer.post(`/api/v1/correlations/${c.id}/decision`, { status: 'confirmed', note: 'looks right' }).expect(403);
    expect((await t.analyst.post(`/api/v1/correlations/${c.id}/decision`, { status: 'confirmed', note: 'verified with the host owner' }).expect(200)).body.status).toBe('confirmed');
    expect((await t.viewer.get(`/api/v1/cases/${cases.items[0].id}/timeline`)).body.some((x: any) => /confirmed by analyst/.test(x.text))).toBe(true);
    await t.other.get(`/api/v1/correlations/${c.id}`).expect(404); expect((await t.other.get('/api/v1/correlations')).body).toEqual([]);
  });
  it('does not correlate unrelated hosts or signals far apart in time', async () => {
    const t0 = Date.now();
    await t.analyst.post('/api/v1/signals', { signals: [sig({ host: 'a-1', at: new Date(t0).toISOString() }), sig({ source: 'wazuh', host: 'b-2', at: new Date(t0 + 1000).toISOString() }), sig({ source: 'defender', host: 'a-1', at: new Date(t0 + 5 * 3600_000).toISOString() })] }).expect(201);
    expect((await t.viewer.get('/api/v1/correlations')).body).toHaveLength(0);
  });
});
