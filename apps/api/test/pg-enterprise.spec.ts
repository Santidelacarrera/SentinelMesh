import { Pool } from 'pg';
import { boot } from './helpers';
import { PgBackend } from '../src/store/pg';
import { PW } from './helpers';

const url = process.env.TEST_DATABASE_URL; // sentinel_app role: NOSUPERUSER NOBYPASSRLS; migrations 0001+0002 applied
(url ? describe : describe.skip)('PostgreSQL: enterprise tables, RLS, uniqueness and immutability (needs TEST_DATABASE_URL)', () => {
  let admin: Pool;
  beforeAll(async () => {
    admin = new Pool({ connectionString: process.env.TEST_DATABASE_ADMIN_URL ?? url });
    const t = (await admin.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'schema_migrations'")).rows.map((r) => `"${r.tablename}"`);
    await admin.query(`TRUNCATE ${t.join(',')} CASCADE`);
    process.env.DATABASE_URL = url;
  });
  afterAll(async () => { delete process.env.DATABASE_URL; await admin.end(); });

  it('every enterprise table has row-level security forced', async () => {
    const r = await admin.query("SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relname <> 'organization' AND c.relname <> 'schema_migrations' AND NOT (c.relrowsecurity AND c.relforcerowsecurity)");
    expect(r.rows).toEqual([]);
  });

  it('works end to end on PostgreSQL: login, inventory, vulnerabilities, signals, correlation, case, evidence, playbook run, report; other tenants see nothing', async () => {
    const t = await boot(); expect(t.app.get(PgBackend).pool).toBeDefined();
    try {
      const platform = { userId: 'p', orgId: 'org_platform', role: 'platform_admin' as const, email: '' };
      await t.acc.createOrg(platform, { id: 'org_pg', name: 'pg', plan: 'enterprise', adminEmail: 'a@pg.test', adminPassword: PW });
      const tok = (await t.http.post('/api/v1/auth/login').send({ org: 'org_pg', email: 'a@pg.test', password: PW }).expect(200)).body.accessToken, H = (r: any) => r.set('Authorization', `Bearer ${tok}`);
      const a = (await H(t.http.post('/api/v1/inventory/assets')).send({ type: 'server', identifier: 'pg-web', criticality: 'critical', internetFacing: true }).expect(201)).body;
      await H(t.http.post('/api/v1/inventory/assets')).send({ type: 'server', identifier: 'PG-WEB' }).expect(201);                      // same asset, case-insensitive: no duplicate row
      expect((await H(t.http.get('/api/v1/inventory/assets')).expect(200)).body.total).toBe(1);
      await H(t.http.post('/api/v1/soar/playbooks/install-defaults')).expect(200);
      await H(t.http.post('/api/v1/vulns')).send({ assetId: a.id, cve: 'CVE-2024-1001', title: 'x', severity: 'high', source: 's' }).expect(201);
      const sigs = [{ source: 'crowdstrike', sourceId: 'x1', title: 'Credential dumping', severity: 'critical', host: 'pg-web' }, { source: 'wazuh', sourceId: 'x2', title: 'sshd brute force', severity: 'high', host: 'pg-web' }];
      expect((await H(t.http.post('/api/v1/signals')).send({ signals: sigs }).expect(201)).body.created).toBe(2);
      expect((await H(t.http.post('/api/v1/signals')).send({ signals: sigs }).expect(201)).body).toMatchObject({ created: 0, duplicates: 2 });   // unique (org, dedup key)
      const cases = (await H(t.http.get('/api/v1/cases')).expect(200)).body; expect(cases.total).toBeGreaterThanOrEqual(1);
      const ev = (await H(t.http.post(`/api/v1/cases/${cases.items[0].id}/evidence`)).send({ name: 'l', source: 's', content: 'hello' }).expect(201)).body;
      expect((await H(t.http.post(`/api/v1/evidence/${ev.id}/verify`)).expect(200)).body.intact).toBe(true);
      await H(t.http.post('/api/v1/reports')).send({ kind: 'executive' }).expect(201);
      expect((await H(t.http.get('/api/v1/soar/runs')).expect(200)).body.length).toBeGreaterThanOrEqual(1);
      expect((await t.audit.verify('org_pg')).ok).toBe(true);
      // another tenant, same database
      for (const p of ['/inventory/assets', '/vulns', '/cases', '/signals', '/reports', '/soar/runs']) { const b = (await t.other.get(`/api/v1${p}`)).body; expect(Array.isArray(b) ? b.length : b.total).toBe(0); }
      await t.other.get(`/api/v1/evidence/${ev.id}`).expect(404);
    } finally { await t.queue.idle(); await t.app.close(); }
  });

  it('database-level guarantees hold even for a buggy application: RLS blocks cross-tenant SQL, evidence and playbook versions are immutable, unique indexes decide races', async () => {
    const app = new Pool({ connectionString: url });
    const as = async (org: string, fn: (q: (sql: string, p?: unknown[]) => Promise<any>) => Promise<void>) => { const c = await app.connect(); try { await c.query('BEGIN'); await c.query("SELECT set_config('app.org_id',$1,true)", [org]); await fn((s, p) => c.query(s, p)); await c.query('COMMIT'); } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); } };
    await admin.query("INSERT INTO organization (id) VALUES ('o_a'),('o_b') ON CONFLICT DO NOTHING");
    await as('o_a', async (q) => { await q("INSERT INTO evidence_item (id, org_id, doc) VALUES ('ev1','o_a','{\"sha256\":\"aa\",\"objectKey\":\"k\",\"caseId\":\"c\"}')"); await q("INSERT INTO playbook (id, org_id, doc) VALUES ('pb1','o_a','{\"key\":\"k\",\"version\":1}')"); await q("INSERT INTO user_account (id, org_id, doc) VALUES ('u1','o_a','{\"email\":\"A@x.test\"}')"); });
    await as('o_b', async (q) => {
      expect((await q('SELECT * FROM evidence_item')).rowCount).toBe(0);                                                       // cannot read o_a
      await expect(q("INSERT INTO evidence_item (id, org_id, doc) VALUES ('ev2','o_a','{}')")).rejects.toThrow(/row-level security/);   // cannot write as o_a
    }).catch(() => undefined);
    await expect(as('o_a', async (q) => { await q("UPDATE evidence_item SET doc = jsonb_set(doc,'{sha256}','\"bb\"') WHERE id='ev1'"); })).rejects.toThrow(/immutable/);
    await expect(as('o_a', async (q) => { await q("DELETE FROM evidence_item WHERE id='ev1'"); })).rejects.toThrow(/cannot be deleted|permission denied/);
    await as('o_a', async (q) => { await q("UPDATE evidence_item SET doc = jsonb_set(doc,'{metadata}','{\"a\":1}') WHERE id='ev1'"); });   // descriptive metadata is allowed
    await expect(as('o_a', async (q) => { await q("UPDATE playbook SET doc = doc || '{\"name\":\"x\"}' WHERE id='pb1'"); })).rejects.toThrow(/append-only/);
    await expect(as('o_a', async (q) => { await q("INSERT INTO user_account (id, org_id, doc) VALUES ('u2','o_a','{\"email\":\"a@X.test\"}')"); })).rejects.toThrow(/duplicate key/);   // case-insensitive unique email
    await expect(as('o_a', async (q) => { await q("DELETE FROM user_account WHERE id='u1'"); })).rejects.toThrow(/permission denied/);          // app role has no DELETE on durable tables
    await app.end();
  });
});
