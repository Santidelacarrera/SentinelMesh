import { boot, Env } from './helpers';

let t: Env;
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });

/** Seeds org_acme with one record of every kind, returning the ids a hostile tenant would try to reach. */
async function seed() {
  const a = (await t.analyst.post('/api/v1/inventory/assets', { type: 'web_app', identifier: 'shop', criticality: 'critical', internetFacing: true })).body;
  const v = (await t.analyst.post('/api/v1/vulns', { assetId: a.id, cve: 'CVE-2024-1234', title: 'x', severity: 'high', source: 's' })).body;
  const i = (await t.analyst.post('/api/v1/iam/identities', { kind: 'human', name: 'Ann', provider: 'p', externalId: 'a', entitlements: ['*'] })).body;
  const c = (await t.analyst.post('/api/v1/cases', { name: 'c', severity: 'high' })).body;
  const e = (await t.analyst.post(`/api/v1/cases/${c.id}/evidence`, { name: 'e', source: 's', content: 'secret evidence' })).body;
  const r = (await t.analyst.post('/api/v1/reports', { kind: 'technical' })).body;
  await t.analyst.post('/api/v1/soar/playbooks/install-defaults');
  await t.analyst.post('/api/v1/signals', { signals: [{ source: 'crowdstrike', sourceId: 's1', title: 'x', severity: 'critical', host: 'shop' }] });
  const run = (await t.viewer.get('/api/v1/soar/runs')).body[0];
  return { a, v, i, c, e, r, run };
}

describe('OWASP API1/API5: broken object-level authorisation — a hostile tenant gets nothing', () => {
  it('every by-id read and write on another organisation\'s objects is a 404/403, never data', async () => {
    const s = await seed();
    const reads = [`/api/v1/inventory/assets/${s.a.id}`, `/api/v1/iam/identities/${s.i.id}`, `/api/v1/cases/${s.c.id}`, `/api/v1/cases/${s.c.id}/timeline`, `/api/v1/cases/${s.c.id}/evidence`, `/api/v1/evidence/${s.e.id}`, `/api/v1/evidence/${s.e.id}/content`, `/api/v1/reports/${s.r.id}/pdf`, `/api/v1/soar/runs/${s.run.id}`];
    for (const p of reads) { const res = await t.other.get(p); expect([403, 404]).toContain(res.status); expect(JSON.stringify(res.body)).not.toMatch(/secret evidence|shop|Ann/); }
    const writes: Array<[string, object]> = [[`/api/v1/vulns/${s.v.id}/status`, { status: 'resolved' }], [`/api/v1/cases/${s.c.id}/status`, { status: 'investigating' }], [`/api/v1/cases/${s.c.id}/comments`, { text: 'x' }], [`/api/v1/cases/${s.c.id}/assign`, { assigneeId: null }],
      [`/api/v1/cases/${s.c.id}/evidence`, { name: 'planted', source: 'x', content: 'x' }], [`/api/v1/cases/${s.c.id}/evidence/export`, { purpose: 'exfiltration attempt' }], [`/api/v1/evidence/${s.e.id}/metadata`, { metadata: { a: 1 }, reason: 'tamper attempt' }], [`/api/v1/evidence/${s.e.id}/verify`, {}],
      [`/api/v1/iam/identities/${s.i.id}/propose-reduction`, {}], [`/api/v1/inventory/assets/${s.a.id}/ownership/challenge`, {}], [`/api/v1/inventory/assets/${s.a.id}/scope`, { inScope: true }], [`/api/v1/soar/runs/${s.run.id}/stop`, { reason: 'denial of service' }]];
    for (const [p, b] of writes) expect([403, 404]).toContain((await t.other.post(p, b)).status);
    expect((await t.db.cases.get('org_acme', s.c.id))!.timeline).toHaveLength(2);                         // only the owner's own entries (opened + evidence captured): nothing from the hostile tenant
    expect((await t.db.evidence.list('org_acme'))).toHaveLength(1);
  });
  it('every list endpoint returns nothing for a tenant that owns nothing', async () => {
    await seed();
    for (const p of ['/inventory/assets', '/vulns', '/exposures/findings', '/exposures/history', '/ctem/attack-paths', '/ctem/priorities', '/iam/identities', '/iam/risks', '/iam/changes', '/signals', '/correlations', '/cases', '/reports', '/soar/runs', '/soar/approvals', '/connectors', '/notifications/channels', '/notifications/log', '/findings', '/approvals', '/executions', '/incidents', '/audit']) {
      const b = (await t.other.get(`/api/v1${p}`)).body; const n = Array.isArray(b) ? b.length : (b.total ?? b.items?.length ?? b.entries?.length ?? 0);
      expect({ p, n }).toEqual({ p, n: 0 });
    }
    expect((await t.other.get('/api/v1/soar/playbooks')).body).toEqual([]);
  });
  it('request-supplied tenant hints cannot widen access: orgId in the body is rejected and x-tenant must match', async () => {
    await t.other.post('/api/v1/inventory/assets', { type: 'server', identifier: 'x1', orgId: 'org_acme' }).expect(400);
    await t.http.get('/api/v1/cases').set('x-api-key', 'other-org-analyst').set('x-tenant', 'org_acme').expect(403);
  });
});

describe('OWASP API2/API3/API6: authentication, excessive exposure, mass assignment', () => {
  it('every protected route refuses anonymous and malformed credentials', async () => {
    for (const p of ['/inventory/assets', '/vulns', '/iam/identities', '/cases', '/reports', '/soar/runs', '/connectors', '/users', '/platform/orgs', '/privacy/export', '/dashboard/executive', '/ops/health', '/audit']) {
      expect({ p, s: (await t.http.get(`/api/v1${p}`)).status }).toEqual({ p, s: 401 });
      expect((await t.http.get(`/api/v1${p}`).set('Authorization', 'Bearer smt.garbage.x.y')).status).toBe(401);
      expect((await t.http.get(`/api/v1${p}`).set('x-api-key', 'guess')).status).toBe(401);
    }
  });
  it('privilege escalation is blocked at every sensitive operation', async () => {
    for (const [who, path, body] of [[t.viewer, '/inventory/assets', { type: 'server', identifier: 'x' }], [t.analyst, '/users', { email: 'a@b.test', password: 'Passw0rd!Passw0rd', role: 'admin' }], [t.analyst, '/soar/automation', { automatedEnabled: true }], [t.analyst, '/connectors', { kind: 'wazuh', name: 'x', baseUrl: 'https://x.test' }],
      [t.analyst, '/privacy/retention', { signalsDays: 30 }], [t.approver, '/platform/orgs', { id: 'org_evil', name: 'x', adminEmail: 'a@b.test', adminPassword: 'Passw0rd!Passw0rd' }], [t.analyst, '/approvals/x/decision', { decision: 'approved' }], [t.viewer, '/reports', { kind: 'executive' }]] as const)
      expect({ path, s: (await who.post(`/api/v1${path}`, body as object)).status }).toEqual({ path, s: 403 });
  });
  it('unknown fields are rejected (no mass assignment) and prototype-pollution payloads do nothing', async () => {
    await t.analyst.post('/api/v1/vulns', { assetId: 'a', title: 't', severity: 'low', source: 's', status: 'resolved', priority: { score: 0 } }).expect(400);
    await t.analyst.post('/api/v1/cases', { name: 'x', severity: 'low', status: 'closed', number: 99 }).expect(400);
    const res = await t.http.post('/api/v1/cases').set('x-api-key', 'dev-analyst').set('content-type', 'application/json').send('{"name":"x","severity":"low","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}');
    expect(res.status).toBe(400); expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
  it('responses never expose secrets, hashes or storage keys', async () => {
    const s = await seed(); const dump = JSON.stringify([(await t.analyst.get(`/api/v1/evidence/${s.e.id}`)).body, (await t.analyst.get('/api/v1/reports')).body, (await t.as('admin-key').get('/api/v1/users')).body, (await t.as('admin-key').get('/api/v1/connectors')).body]);
    expect(dump).not.toMatch(/objectKey|passwordHash|scrypt\$|credentialsEnc|targetEnc|evidence\/org_acme/);
  });
});

describe('injection, abuse and hardening', () => {
  it('query and body strings are data: SQL/NoSQL/JSON-containment payloads match nothing and break nothing', async () => {
    await seed();
    for (const q of ["'; DROP TABLE vulnerability;--", '{"$ne":null}', '" OR 1=1 --', '../../etc/passwd', '%00', '<script>alert(1)</script>']) {
      for (const p of ['/vulns', '/inventory/assets', '/cases', '/iam/identities']) { const r = await t.analyst.get(`/api/v1${p}?q=${encodeURIComponent(q)}&status=${encodeURIComponent(q)}&limit=${encodeURIComponent(q)}`); expect(r.status).toBeLessThan(500); }
    }
    expect((await t.analyst.get('/api/v1/vulns')).body.total).toBe(1);                                   // data still there
    const a = (await t.analyst.post('/api/v1/inventory/assets', { type: 'domain', identifier: 'a.test"; DROP--' })).status; expect(a).toBe(400);
  });
  it('rejects oversized bodies, applies security headers and hides the framework', async () => {
    const big = await t.http.post('/api/v1/signals').set('x-api-key', 'dev-analyst').send({ signals: [{ source: 's', sourceId: 'x', title: 'y'.repeat(11 * 1024 * 1024), severity: 'low' }] });
    expect([400, 413]).toContain(big.status);
    const r = await t.viewer.get('/api/v1/me');
    expect(r.headers).toMatchObject({ 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'cache-control': 'no-store' }); expect(r.headers['x-powered-by']).toBeUndefined(); expect(r.headers['content-security-policy']).toContain("default-src 'none'");
  });
  it('the audit chain survives all of the above and still verifies', async () => {
    await seed(); await t.other.get('/api/v1/cases'); expect((await t.audit.verify('org_acme')).ok).toBe(true);
    t.audit.memory._tamper('org_acme', 1, { actor: 'mallory' }); expect((await t.audit.verify('org_acme')).ok).toBe(false);          // and tampering is detected
  });
});
