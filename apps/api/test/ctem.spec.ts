import { boot, Env } from './helpers';
import { prioritize } from '../src/ctem/priority';
import { analyzeAttackPaths } from '../src/ctem/attack-paths';
import { parseEpss, parseKev, parseNvd } from '../src/ctem/intel';

const asset = (o: object = {}) => ({ name: 'web', criticality: 'high', internetFacing: true, environment: 'prod', controls: [] as string[], ...o }) as any;

describe('contextual prioritisation (pure)', () => {
  it('explains every point and is not just CVSS', () => {
    const a = prioritize({ severity: 'high', cvss: { score: 7.5 }, confidence: 'confirmed', status: 'open' }, { asset: asset({ internetFacing: false, criticality: 'low', controls: ['waf', 'edr'] }) });
    const b = prioritize({ severity: 'high', cvss: { score: 7.5 }, kev: true, epss: { score: 0.9 }, confidence: 'confirmed', status: 'open' }, { asset: asset({ criticality: 'critical' }), privilegedIdentities: 2, criticalDependents: 1 });
    expect(b.score).toBeGreaterThan(a.score + 40);
    expect(a.factors.find((f) => f.name === 'Compensating controls')!.points).toBe(-10);
    expect(b.factors.map((f) => f.name)).toEqual(expect.arrayContaining(['Known exploited (CISA KEV)', 'Exploit probability (EPSS)', 'Privileges involved']));
    expect(b.explanation).toMatch(/Main drivers/);
    expect(a.level).not.toBe('immediate');
  });
  it('does not invent missing intelligence and scales by detection confidence', () => {
    const none = prioritize({ severity: 'medium', confidence: 'confirmed', status: 'open' });
    expect(none.factors.find((f) => f.name.startsWith('Exploit probability'))!.points).toBe(0);
    expect(none.factors.find((f) => f.name.startsWith('Known exploited'))!.detail).toMatch(/not in the imported/);
    const unverified = prioritize({ severity: 'medium', confidence: 'unverified', status: 'open' });
    expect(unverified.score).toBeLessThan(none.score);
    expect(unverified.factors.some((f) => f.name === 'Detection confidence')).toBe(true);
  });
  it('KEV on a confirmed Internet-facing asset is always immediate', () => {
    const r = prioritize({ severity: 'low', cvss: { score: 3.1 }, kev: true, confidence: 'confirmed', status: 'open' }, { asset: asset({ criticality: 'low', controls: ['waf', 'edr', 'segmentation'], environment: 'dev' }) });
    expect(r.level).toBe('immediate'); expect(r.explanation).toMatch(/Override/);
  });
});

describe('intel parsers', () => {
  it('parse NVD, KEV and EPSS and ignore junk', () => {
    expect(parseNvd({ vulnerabilities: [{ cve: { id: 'cve-2024-1', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, vectorString: 'CVSS:3.1/x', version: '3.1' } }] } } }, { cve: { id: 'bad' } }] })).toEqual([]);
    const n = parseNvd({ vulnerabilities: [{ cve: { id: 'CVE-2024-0001', descriptions: [{ lang: 'en', value: 'd' }], weaknesses: [{ description: [{ value: 'CWE-79' }] }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, version: '3.1' } }] } } }] });
    expect(n[0]).toMatchObject({ cve: 'CVE-2024-0001', cvss: { score: 9.8 }, cwe: 'CWE-79', description: 'd' });
    expect(parseKev({ vulnerabilities: [{ cveID: 'CVE-2024-0001', dueDate: '2024-06-01' }] })[0]).toEqual({ cve: 'CVE-2024-0001', kev: true, kevDueDate: '2024-06-01' });
    expect(parseEpss('#model\ncve,epss,percentile\nCVE-2024-0001,0.97,0.99\nCVE-2024-0002,5,1')).toHaveLength(1);
    expect(() => parseKev({ nope: 1 })).toThrow(); expect(() => parseEpss(42)).toThrow();
  });
});

describe('attack paths (pure)', () => {
  const A = (id: string, o: object = {}) => ({ id, orgId: 'o', type: 'server', identifier: id, name: id, source: 't', firstSeen: '', lastSeen: '', status: 'active', criticality: 'medium', internetFacing: false, environment: 'prod', tags: [], controls: [], ownership: { status: 'unverified' }, inScope: false, ...o }) as any;
  const R = (from: string, to: string, kind: string, confidence = 0.9) => ({ id: `${from}-${to}`, orgId: 'o', from, to, kind, source: 't', confidence, createdAt: '' }) as any;
  const I = (id: string, o: object = {}) => ({ id, orgId: 'o', kind: 'service', name: id, provider: 'aws', externalId: id, privileged: true, status: 'active', entitlements: ['*'], authMethods: [], createdAt: '', lastSeen: '', assetIds: [], ...o }) as any;
  const g = (o: object = {}) => ({ assets: [A('web', { internetFacing: true }), A('db', { criticality: 'critical' }), A('isolated', { criticality: 'critical' })], identities: [I('svc')], relations: [R('web', 'svc', 'authenticates_to'), R('svc', 'db', 'admin_of')], vulns: [], exposures: [], signals: [], ...o });
  it('finds entry → identity → critical target and labels it theoretical', () => {
    const paths = analyzeAttackPaths(g({ vulns: [{ id: 'v1', assetId: 'web', status: 'open', confidence: 'confirmed', cve: 'CVE-2024-1', kev: true, title: 't' }] }));
    expect(paths).toHaveLength(1);
    expect(paths[0]).toMatchObject({ hops: 2, status: 'theoretical' });
    expect(paths[0].nodes.map((n) => n.id)).toEqual(['web', 'svc', 'db']);
    expect(paths[0].privileges[0]).toMatchObject({ identity: 'svc', privileged: true });
    expect(paths[0].evidence[0]).toMatchObject({ type: 'vulnerability', id: 'v1' });
    expect(paths[0].impact).toMatch(/privileged/);
  });
  it('lowers confidence without a known foothold, honours edge confidence and never reaches unconnected targets', () => {
    const withVuln = analyzeAttackPaths(g({ vulns: [{ id: 'v1', assetId: 'web', status: 'open', confidence: 'confirmed', title: 't' }] }))[0].confidence;
    const bare = analyzeAttackPaths(g())[0];
    expect(bare.confidence).toBeLessThan(withVuln / 3);
    expect(bare.notes.join(' ')).toMatch(/hypothetical/);
    expect(analyzeAttackPaths(g()).some((p) => p.target.id === 'isolated')).toBe(false);
  });
  it('treats runs_on as host→container, marks alerts as corroboration, and skips resolved/accepted vulns', () => {
    const gr = g({ assets: [A('web', { internetFacing: true }), A('c1', { criticality: 'critical' })], identities: [], relations: [R('c1', 'web', 'runs_on')] });
    expect(analyzeAttackPaths(gr)[0].nodes.map((n) => n.id)).toEqual(['web', 'c1']);
    const al = analyzeAttackPaths({ ...gr, signals: [{ id: 's1', assetId: 'c1', source: 'wazuh', title: 'alert' } as any] })[0];
    expect(al.status).toBe('corroborated'); expect(al.evidence.some((e) => e.type === 'signal')).toBe(true);
    expect(analyzeAttackPaths({ ...gr, vulns: [{ id: 'v', assetId: 'web', status: 'resolved', confidence: 'confirmed', title: 't' } as any] })[0].evidence).toHaveLength(0);
  });
});

let t: Env;
let dnsRecords: Record<string, string[]> = {};
let tlsAnswer: any = { authorized: true, validTo: new Date(Date.now() + 200 * 86400000).toISOString() };
beforeEach(async () => { dnsRecords = {}; tlsAnswer = { authorized: true, validTo: new Date(Date.now() + 200 * 86400000).toISOString() }; t = await boot({ dns: async (n) => dnsRecords[n] ?? [], tls: async () => tlsAnswer }); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });
const mk = (b: object) => t.analyst.post('/api/v1/inventory/assets', b);

describe('inventory & vulnerabilities (API)', () => {
  it('discovers assets idempotently, normalises identifiers, validates, records history and isolates tenants', async () => {
    const a = await mk({ type: 'domain', identifier: 'API.Acme.Test', internetFacing: true, criticality: 'high', source: 'dns' }).expect(201);
    expect(a.body.identifier).toBe('api.acme.test');
    const again = await mk({ type: 'domain', identifier: 'api.acme.test', criticality: 'critical' }).expect(201);
    expect(again.body.id).toBe(a.body.id); expect(again.body.criticality).toBe('critical');
    await mk({ type: 'domain', identifier: 'not a host' }).expect(400);
    await mk({ type: 'ip', identifier: '999.1.1.1' }).expect(400);
    await mk({ type: 'domain', identifier: 'x.acme.test', unknown: 1 }).expect(400);
    const d = (await t.viewer.get(`/api/v1/inventory/assets/${a.body.id}`).expect(200)).body;
    expect(d.history.map((h: any) => h.type)).toEqual(expect.arrayContaining(['asset_discovered', 'asset_changed']));
    await t.other.get(`/api/v1/inventory/assets/${a.body.id}`).expect(404);
    expect((await t.other.get('/api/v1/inventory/assets').expect(200)).body.total).toBe(0);
    await t.viewer.post('/api/v1/inventory/assets', { type: 'domain', identifier: 'v.acme.test' }).expect(403);
    expect((await t.audit.list('org_acme')).map((e) => e.event)).toEqual(expect.arrayContaining(['asset.discovered', 'asset.changed']));
  });
  it('relations require existing nodes of the same org', async () => {
    const a = (await mk({ type: 'server', identifier: 'srv1' })).body, b = (await mk({ type: 'database', identifier: 'db1' })).body;
    await t.analyst.post('/api/v1/inventory/relations', { from: a.id, to: b.id, kind: 'depends_on' }).expect(201);
    await t.analyst.post('/api/v1/inventory/relations', { from: a.id, to: 'ast_nope', kind: 'depends_on' }).expect(404);
    const o = (await t.other.post('/api/v1/inventory/assets', { type: 'server', identifier: 'foreign' })).body;
    await t.analyst.post('/api/v1/inventory/relations', { from: a.id, to: o.id, kind: 'depends_on' }).expect(404);
  });
  it('imports NVD/KEV/EPSS, enriches vulnerabilities, re-prioritises, and refuses to invent scores', async () => {
    const a = (await mk({ type: 'web_app', identifier: 'shop', internetFacing: true, criticality: 'critical' })).body;
    await t.analyst.post('/api/v1/vulns', { assetId: a.id, cve: 'CVE-2024-9999', title: 'Unknown CVE', source: 'scanner' }).expect(400);   // no severity/CVSS anywhere
    const v0 = (await t.analyst.post('/api/v1/vulns', { assetId: a.id, cve: 'CVE-2024-9999', title: 'RCE in lib', severity: 'high', source: 'scanner', confidence: 'confirmed' }).expect(201)).body;
    expect(v0.cvss).toBeUndefined(); expect(v0.epss).toBeUndefined(); expect(v0.kev).toBeUndefined();
    const before = v0.priority.score;
    await t.analyst.post('/api/v1/intel/import', { kind: 'nvd', payload: { vulnerabilities: [{ cve: { id: 'CVE-2024-9999', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, version: '3.1' } }] } } }] } }).expect(200);
    await t.analyst.post('/api/v1/intel/import', { kind: 'kev', payload: { vulnerabilities: [{ cveID: 'CVE-2024-9999', dueDate: '2020-01-01' }] } }).expect(200);
    const r = await t.analyst.post('/api/v1/intel/import', { kind: 'epss', payload: 'cve,epss,percentile\nCVE-2024-9999,0.93,0.99' }).expect(200);
    expect(r.body.vulnerabilitiesReprioritized).toBeGreaterThanOrEqual(0);
    const v1 = (await t.viewer.get('/api/v1/vulns').expect(200)).body.items[0];
    expect(v1).toMatchObject({ kev: true, cvss: { score: 9.8 }, epss: { score: 0.93 }, dueDate: '2020-01-01' });
    expect(v1.priority.score).toBeGreaterThan(before); expect(v1.priority.level).toBe('immediate');
    expect(v1.enrichedFrom).toEqual(expect.arrayContaining(['cvss', 'epss', 'kev']));
    const dup = (await t.analyst.post('/api/v1/vulns', { assetId: a.id, cve: 'CVE-2024-9999', title: 'RCE in lib', severity: 'high', source: 'scanner' }).expect(201)).body;
    expect(dup.id).toBe(v1.id);                                                                   // idempotent per fingerprint
    await t.analyst.post('/api/v1/intel/import', { kind: 'kev', payload: { nope: 1 } }).expect(400);
    const pr = (await t.viewer.get('/api/v1/ctem/priorities').expect(200)).body;
    expect(pr[0]).toMatchObject({ id: v1.id, kev: true }); expect(pr[0].priority.explanation).toMatch(/KEV/);
  });
  it('risk acceptance needs a justification; status changes are audited; other tenants cannot touch it', async () => {
    const a = (await mk({ type: 'server', identifier: 'srv2' })).body;
    const v = (await t.analyst.post('/api/v1/vulns', { assetId: a.id, title: 'weak cipher', severity: 'low', source: 'manual' }).expect(201)).body;
    await t.analyst.post(`/api/v1/vulns/${v.id}/status`, { status: 'accepted' }).expect(400);
    await t.other.post(`/api/v1/vulns/${v.id}/status`, { status: 'resolved' }).expect(404);
    await t.analyst.post(`/api/v1/vulns/${v.id}/status`, { status: 'accepted', note: 'legacy device, retiring in Q3' }).expect(200);
    expect((await t.audit.list('org_acme')).some((e) => e.event === 'vuln.status_changed')).toBe(true);
  });
  it('bridges scanner findings (CVE rule ids) to inventory vulnerabilities as "suspected"', async () => {
    const a = (await mk({ type: 'container', identifier: 'auth-api', name: 'auth-api' })).body;
    await t.analyst.post('/api/v1/scans/ingest', { format: 'trivy', source: 't', report: { Results: [{ Target: 'auth-api', Vulnerabilities: [{ VulnerabilityID: 'CVE-2024-45337', PkgName: 'x', Severity: 'CRITICAL', Title: 'bypass' }] }] } }).expect(201);
    const r = (await t.analyst.post('/api/v1/vulns/import-findings').expect(200)).body;
    expect(r.created).toBe(1);
    const v = (await t.viewer.get(`/api/v1/vulns?assetId=${a.id}`)).body.items[0];
    expect(v).toMatchObject({ cve: 'CVE-2024-45337', confidence: 'suspected' });
  });
});

describe('attack surface (API)', () => {
  it('ownership by DNS TXT gates scope and active TLS checks; a bad record is refused', async () => {
    const a = (await mk({ type: 'domain', identifier: 'www.acme.test', internetFacing: true })).body;
    await t.analyst.post(`/api/v1/inventory/assets/${a.id}/scope`, { inScope: true }).expect(403);
    await t.analyst.post(`/api/v1/inventory/assets/${a.id}/tls-check`, {}).expect(403);
    const ch = (await t.analyst.post(`/api/v1/inventory/assets/${a.id}/ownership/challenge`).expect(201)).body;
    expect(ch.record).toBe('_sentinelmesh.www.acme.test');
    await t.analyst.post(`/api/v1/inventory/assets/${a.id}/ownership/verify`, { method: 'dns_txt' }).expect(400);
    dnsRecords[ch.record] = [ch.value];
    await t.analyst.post(`/api/v1/inventory/assets/${a.id}/ownership/verify`, { method: 'dns_txt' }).expect(200);
    await t.analyst.post(`/api/v1/inventory/assets/${a.id}/scope`, { inScope: true }).expect(200);
    const ok = (await t.analyst.post(`/api/v1/inventory/assets/${a.id}/tls-check`, {}).expect(200)).body;
    expect(ok.opened).toBe(0);
    await t.other.post(`/api/v1/inventory/assets/${a.id}/tls-check`, {}).expect(404);
  });
  it('flags certificates close to expiry, keeps history, and resolves them when renewed', async () => {
    const a = (await mk({ type: 'domain', identifier: 'pay.acme.test', internetFacing: true })).body;
    await t.analyst.post(`/api/v1/inventory/assets/${a.id}/ownership/verify`, { method: 'manual_attestation', note: 'registered by the platform team' }).expect(200);
    await t.analyst.post(`/api/v1/inventory/assets/${a.id}/scope`, { inScope: true }).expect(200);
    tlsAnswer = { authorized: true, validTo: new Date(Date.now() + 5 * 86400000).toISOString(), issuer: 'Test CA' };
    expect((await t.analyst.post(`/api/v1/inventory/assets/${a.id}/tls-check`, {}).expect(200)).body.opened).toBe(1);
    const e = (await t.viewer.get('/api/v1/exposures/findings?status=open').expect(200)).body.items[0];
    expect(e).toMatchObject({ kind: 'tls_expiring', confidence: 'confirmed' }); expect(e.evidence.join(' ')).toMatch(/notAfter/);
    tlsAnswer = { authorized: true, validTo: new Date(Date.now() + 90 * 86400000).toISOString() };
    expect((await t.analyst.post(`/api/v1/inventory/assets/${a.id}/tls-check`, {}).expect(200)).body.resolved).toBe(1);
    expect((await t.viewer.get(`/api/v1/exposures/history?assetId=${a.id}`)).body.map((h: any) => h.type)).toEqual(expect.arrayContaining(['exposure_opened', 'exposure_resolved', 'ownership_verified']));
  });
  it('false-positive control: first sighting is suspected, the second confirms, complete scans close the missing', async () => {
    const a = (await mk({ type: 'server', identifier: 'edge1', internetFacing: true })).body;
    const obs = (title: string) => ({ kind: 'open_port', title, evidence: ['nmap: 3389/tcp open'], confidence: 'suspected' });
    const scan = (list: object[], complete = false) => t.analyst.post('/api/v1/exposures/observe', { assetId: a.id, source: 'scanner-x', complete, coverKinds: ['open_port'], observations: list }).expect(200);
    expect((await scan([obs('RDP 3389 exposed')])).body.opened).toBe(1);
    let e = (await t.viewer.get('/api/v1/exposures/findings')).body.items[0]; expect(e.confidence).toBe('suspected'); expect(e.seen).toBe(1);
    expect((await scan([obs('RDP 3389 exposed')])).body.confirmed).toBe(1);
    e = (await t.viewer.get('/api/v1/exposures/findings')).body.items[0]; expect(e.confidence).toBe('confirmed'); expect(e.seen).toBe(2);
    expect((await scan([], true)).body.resolved).toBe(1);
    expect((await t.viewer.get('/api/v1/exposures/findings?status=open')).body.total).toBe(0);
    await t.analyst.post('/api/v1/exposures/observe', { assetId: a.id, source: 's', observations: [{ kind: 'open_port', title: 'x', evidence: [] }] }).expect(400);   // evidence is mandatory
  });
  it('marks forgotten internet-facing assets as stale with an exposure', async () => {
    const a = (await mk({ type: 'subdomain', identifier: 'old.acme.test', internetFacing: true })).body;
    await t.db.inventory.update('org_acme', a.id, { lastSeen: new Date(Date.now() - 90 * 86400000).toISOString() });
    expect((await t.analyst.post('/api/v1/inventory/assets/stale-check', { days: 30 }).expect(200)).body.markedStale).toBe(1);
    expect((await t.viewer.get('/api/v1/exposures/findings')).body.items[0].kind).toBe('forgotten_asset');
    expect((await t.viewer.get(`/api/v1/inventory/assets/${a.id}`)).body.asset.status).toBe('stale');
  });
  it('attack paths over the API: entry → privileged identity → critical data store, tenant-scoped, theoretical', async () => {
    const web = (await mk({ type: 'web_app', identifier: 'portal', internetFacing: true })).body, db = (await mk({ type: 'database', identifier: 'ledger', criticality: 'critical' })).body;
    const svc = await t.db.identities.put({ id: 'idn_svc', orgId: 'org_acme', kind: 'service', name: 'portal-svc', provider: 'aws', externalId: 'x', privileged: true, status: 'active', entitlements: ['s3:*'], authMethods: ['key'], createdAt: '', lastSeen: '', assetIds: [] });
    await t.analyst.post('/api/v1/inventory/relations', { from: web.id, to: svc.id, kind: 'authenticates_to' }).expect(201);
    await t.analyst.post('/api/v1/inventory/relations', { from: svc.id, to: db.id, kind: 'admin_of' }).expect(201);
    await t.analyst.post('/api/v1/vulns', { assetId: web.id, cve: 'CVE-2024-1111', title: 'SSRF', severity: 'high', confidence: 'confirmed', source: 'dast' }).expect(201);
    const p = (await t.viewer.get('/api/v1/ctem/attack-paths').expect(200)).body;
    expect(p).toHaveLength(1); expect(p[0].status).toBe('theoretical'); expect(p[0].nodes.map((n: any) => n.name)).toEqual(['portal', 'portal-svc', 'ledger']);
    expect((await t.other.get('/api/v1/ctem/attack-paths').expect(200)).body).toEqual([]);
    const v = (await t.viewer.get('/api/v1/vulns')).body.items[0];
    expect(v.priority.factors.find((f: any) => f.name === 'Privileges involved').points).toBeGreaterThan(0);
    expect(v.priority.factors.find((f: any) => f.name === 'Business impact (blast radius)').points).toBe(5);
  });
  it('plan gating: a starter org keeps inventory/vulns but not attack surface or paths', async () => {
    await t.db.orgs.put({ id: 'org_other', orgId: 'org_platform', name: 'o', plan: 'starter', status: 'active', retentionDays: 365, createdAt: '', createdBy: 'x' });
    await t.other.get('/api/v1/inventory/assets').expect(200);
    await t.other.get('/api/v1/exposures/findings').expect(402);
    await t.other.get('/api/v1/ctem/attack-paths').expect(402);
  });
});
