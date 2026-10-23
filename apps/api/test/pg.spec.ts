import { Pool } from 'pg';
import { boot, ORG } from './helpers';
import { PgPersistence } from '../src/store/pg';

const url = process.env.TEST_DATABASE_URL; // role must be NOSUPERUSER NOBYPASSRLS
(url ? describe : describe.skip)('PostgreSQL persistence + RLS (needs TEST_DATABASE_URL)', () => {
  beforeAll(async () => {
    const admin = new Pool({ connectionString: process.env.TEST_DATABASE_ADMIN_URL ?? url });
    await admin.query('TRUNCATE finding, credential_record, workflow_execution, security_workflow, secops_approval, dry_run_plan, vulnerability_scan, asset_context, forensic_snapshot, security_incident, traffic_anomaly, identity_audit, access_policy, audit_trail, organization CASCADE').catch(() => {});
    await admin.end();
    process.env.DATABASE_URL = url;
  });
  afterAll(() => { delete process.env.DATABASE_URL; });

  it('survives a restart: findings, executions, approvals and the audit chain are rehydrated', async () => {
    const t = await boot();
    await t.analyst.post('/api/v1/scans/ingest', { format: 'secrets', source: 'gl', report: { findings: [{ rule: 'aws', secret: 'AKIAIOSFODNN7EXAMPLE', file: 'a.js', repo: 'payments', verified: true }] } }).expect(201);
    const cred = t.db.credentials.list(ORG)[0]; t.secrets.seed(cred.id);
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await t.queue.idle();
    await t.app.get(PgPersistence).flush();
    await t.app.close();

    const t2 = await boot(); // fresh process, empty memory → hydrated from Postgres
    const ex = t2.db.executions.get(ORG, rot.body.executionId)!;
    expect(ex.status).toBe('awaiting_approval');
    expect(t2.db.approvals.list(ORG, (a) => a.status === 'pending')).toHaveLength(1);
    expect(t2.audit.verify(ORG).ok).toBe(true);
    expect(t2.audit.list(ORG).length).toBeGreaterThan(3);
    // and the approval can still be decided & the execution resumed after the "restart"
    const [a] = t2.db.approvals.list(ORG);
    t2.secrets.seed(cred.id); // simulated secret provider is in-memory; re-seed its versions
    await t2.secrets.createVersion(cred.id, `${rot.body.executionId}:create-new-credential`);
    await t2.secrets.setActive(cred.id, 2);
    await t2.approver.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'approved' }).expect(200);
    await t2.queue.idle();
    expect(t2.db.executions.get(ORG, rot.body.executionId)!.status).toBe('succeeded');
    await t2.app.get(PgPersistence).flush();
    await t2.app.close();
  });

  it('RLS: a connection scoped to another org (or none) sees nothing; the audit table is append-only', async () => {
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
