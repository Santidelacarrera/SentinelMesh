import { Pool } from 'pg';
import request from 'supertest';
import { boot, ORG } from './helpers';
import { PgBackend } from '../src/store/pg';

const url = process.env.TEST_DATABASE_URL; // role must be NOSUPERUSER NOBYPASSRLS
(url ? describe : describe.skip)('PostgreSQL backend: stateless replicas + RLS (needs TEST_DATABASE_URL)', () => {
  beforeAll(async () => {
    const admin = new Pool({ connectionString: process.env.TEST_DATABASE_ADMIN_URL ?? url });
    await admin.query('TRUNCATE finding, credential_record, workflow_execution, security_workflow, secops_approval, dry_run_plan, vulnerability_scan, asset_context, forensic_snapshot, security_incident, traffic_anomaly, identity_audit, access_policy, audit_trail, organization CASCADE');
    await admin.end();
    process.env.DATABASE_URL = url;
  });
  afterAll(() => { delete process.env.DATABASE_URL; });

  it('has no in-process state: replica B sees (and can continue) what replica A did', async () => {
    const A = await boot(), B = await boot();   // two API instances, one database, separate memory
    const [pgA] = [A.app.get(PgBackend)];
    expect(pgA.pool).toBeDefined();
    await A.analyst.post('/api/v1/scans/ingest', { format: 'secrets', source: 'gl', report: { findings: [{ rule: 'aws', secret: 'AKIAIOSFODNN7EXAMPLE', file: 'a.js', repo: 'payments', verified: true }] } }).expect(201);
    const cred = (await B.db.credentials.list(ORG))[0];
    expect(cred.maskedValue).toBe('AKIA****LE');
    A.secrets.seed(cred.id); B.secrets.seed(cred.id);
    const rot = await A.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await A.queue.idle();

    const seenByB = (await B.viewer.get(`/api/v1/executions/${rot.body.executionId}`).expect(200)).body;
    expect(seenByB.status).toBe('awaiting_approval');
    const [apr] = (await B.approver.get('/api/v1/approvals?status=pending').expect(200)).body;
    // decide on B; drive the execution on B (A's simulated secret store is separate memory, so replay create/activate there too)
    await B.secrets.createVersion(cred.id, `${rot.body.executionId}:create-new-credential`); await B.secrets.setActive(cred.id, 2);
    await B.approver.post(`/api/v1/approvals/${apr.id}/decision`, { decision: 'approved' }).expect(200);
    await B.queue.idle();
    expect((await A.viewer.get(`/api/v1/executions/${rot.body.executionId}`)).body.status).toBe('succeeded');   // A reads B's work
    expect((await A.viewer.get('/api/v1/audit')).body.verify.ok).toBe(true);
    await A.app.close(); await B.app.close();
  });

  it('a double decision across replicas: exactly one wins, the other gets 409 (row lock)', async () => {
    const A = await boot(), B = await boot();
    await A.analyst.post('/api/v1/iam/audit-roles', { roleName: 'r1', critical: true, grantedActions: ['s3:GetObject', 's3:PutObject'], auditEvents: ['s3:GetObject'], resources: ['*'], submitForApproval: true }).expect(201);
    await A.queue.idle();
    const [apr] = (await A.viewer.get('/api/v1/approvals?status=pending')).body;
    const res = await Promise.all([A.approver.post(`/api/v1/approvals/${apr.id}/decision`, { decision: 'approved' }), B.approver.post(`/api/v1/approvals/${apr.id}/decision`, { decision: 'rejected' })]);
    expect(res.map((r) => r.status).sort()).toEqual([200, 409]);
    await A.app.close(); await B.app.close();
  });

  it('concurrent ingests of the same report across replicas create each finding once', async () => {
    const A = await boot(), B = await boot();
    const report = { runs: [{ tool: { driver: { name: 'x' } }, results: Array.from({ length: 6 }, (_, i) => ({ ruleId: `r${i}`, level: 'error', message: { text: `m${i}` }, locations: [{ physicalLocation: { artifactLocation: { uri: `svc/f${i}.js` } } }] })) }] };
    const rs = await Promise.all([A, B, A, B].map((t) => t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'ci', report })));
    expect(rs.reduce((n, r) => n + r.body.created, 0)).toBe(6);
    expect(rs.reduce((n, r) => n + r.body.duplicates, 0)).toBe(18);
    expect((await A.viewer.get('/api/v1/findings?limit=500')).body.total).toBeGreaterThanOrEqual(6);
    await A.app.close(); await B.app.close();
  });

  it('audit chain stays linear under concurrent writers on different replicas', async () => {
    const A = await boot(), B = await boot();
    await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? A : B).audit.append(ORG, 'u', `evt.${i}`, { i })));
    const entries = await A.audit.list(ORG);
    const seqs = entries.map((e) => e.seq);
    expect(new Set(seqs).size).toBe(seqs.length);
    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
    expect((await B.audit.verify(ORG)).ok).toBe(true);
    await A.app.close(); await B.app.close();
  });

  it('RLS: a connection scoped to another org (or none) sees nothing; audit and workflow versions are append-only', async () => {
    const pool = new Pool({ connectionString: url });
    const q = async (org: string | null, sql: string) => {
      const c = await pool.connect();
      try { await c.query('BEGIN'); if (org) await c.query("SELECT set_config('app.org_id',$1,true)", [org]); const r = await c.query(sql); await c.query('COMMIT'); return r; }
      catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
    };
    expect((await q(ORG, 'SELECT 1 FROM finding')).rowCount).toBeGreaterThan(0);
    expect((await q('org_other', 'SELECT 1 FROM finding')).rowCount).toBe(0);
    expect((await q(null, 'SELECT 1 FROM finding')).rowCount).toBe(0);
    await expect(q('org_other', `INSERT INTO finding (id, org_id, doc) VALUES ('x', '${ORG}', '{"status":"open"}')`)).rejects.toThrow(/row-level security/);
    await expect(q(ORG, `DELETE FROM audit_trail`)).rejects.toThrow(/append-only|permission denied/);
    await expect(q(ORG, `UPDATE security_workflow SET doc = '{}'`)).rejects.toThrow(/append-only|permission denied/);
    await pool.end();
  });
});
void request;
