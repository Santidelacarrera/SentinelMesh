import { Injectable, Logger, OnApplicationShutdown, OnModuleInit } from '@nestjs/common';
import { Pool } from 'pg';
import { Db } from './db';
import { AuditTrail } from '../audit/audit-trail';
import { Collection } from './store';
import { AuditEntry } from './models';

const TABLES: Record<keyof Db, string> = {
  scans: 'vulnerability_scan', assets: 'asset_context', findings: 'finding', credentials: 'credential_record', identityAudits: 'identity_audit',
  policies: 'access_policy', anomalies: 'traffic_anomaly', incidents: 'security_incident', snapshots: 'forensic_snapshot', plans: 'dry_run_plan',
  workflows: 'security_workflow', executions: 'workflow_execution', approvals: 'secops_approval',
};

/**
 * Durable write-through persistence. The in-memory collections stay the read path (sync API); every mutation is
 * queued in order and written inside a transaction that sets `app.org_id`, so PostgreSQL RLS is enforced on every statement.
 * Boot hydrates the collections. Single-writer by design (see docs/architecture.md → limits).
 */
@Injectable()
export class PgPersistence implements OnModuleInit, OnApplicationShutdown {
  private log = new Logger('Pg');
  private chain: Promise<unknown> = Promise.resolve();
  private failed?: Error;
  pool?: Pool;

  private url = process.env.DATABASE_URL;
  constructor(private db: Db, private audit: AuditTrail) {}

  async onModuleInit() {
    if (!this.url) return;
    this.pool = new Pool({ connectionString: this.url, max: 5 });
    await this.hydrate();
    for (const [k, table] of Object.entries(TABLES) as Array<[keyof Db, string]>) {
      (this.db[k] as Collection<any>).onWrite = (row) => this.enqueue(row.orgId, async (c) => {
        await c.query('INSERT INTO organization (id) VALUES ($1) ON CONFLICT DO NOTHING', [row.orgId]);
        const conflict = table === 'security_workflow' ? 'DO NOTHING' : 'DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()';
        await c.query(`INSERT INTO ${table} (id, org_id, doc) VALUES ($1, $2, $3) ON CONFLICT (id) ${conflict}`, [row.id, row.orgId, JSON.stringify(row)]);
      });
    }
    this.audit.onAppend = (e) => this.enqueue(e.orgId, async (c) => {
      await c.query('INSERT INTO organization (id) VALUES ($1) ON CONFLICT DO NOTHING', [e.orgId]);
      await c.query('INSERT INTO audit_trail (id, org_id, seq, at, actor, event, data, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [e.id, e.orgId, e.seq, e.at, e.actor, e.event, JSON.stringify(e.data), e.prevHash, e.hash]);
    });
  }

  private async withOrg<T>(orgId: string, fn: (c: import('pg').PoolClient) => Promise<T>): Promise<T> {
    const c = await this.pool!.connect();
    try {
      await c.query('BEGIN');
      await c.query("SELECT set_config('app.org_id', $1, true)", [orgId]);
      const r = await fn(c); await c.query('COMMIT'); return r;
    } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
  }

  private enqueue(orgId: string, fn: (c: import('pg').PoolClient) => Promise<void>) {
    this.chain = this.chain.then(() => this.withOrg(orgId, fn)).catch((e) => { this.failed = e; this.log.error(`persist failed: ${e.message}`); });
  }

  /** Waits for queued writes; throws if any write failed (so callers/tests can't miss data loss). */
  async flush() { await this.chain; if (this.failed) throw this.failed; }

  private async hydrate() {
    // Hydration must see all tenants, so it enumerates organisations first and reads each under its own RLS context.
    const orgs = (await this.pool!.query('SELECT id FROM organization')).rows.map((r) => r.id as string);
    for (const orgId of orgs) await this.withOrg(orgId, async (c) => {
      for (const [k, table] of Object.entries(TABLES) as Array<[keyof Db, string]>) {
        const rows = (await c.query(`SELECT doc FROM ${table}`)).rows.map((r) => r.doc);
        (this.db[k] as Collection<any>).hydrate(rows);
      }
      const a = (await c.query('SELECT id, org_id, seq, at, actor, event, data, prev_hash, hash FROM audit_trail ORDER BY seq')).rows;
      this.audit.hydrate(a.map((r): AuditEntry => ({ id: r.id, orgId: r.org_id, seq: Number(r.seq), at: new Date(r.at).toISOString(), actor: r.actor, event: r.event, data: r.data, prevHash: r.prev_hash, hash: r.hash })));
    });
  }

  async onApplicationShutdown() { if (this.pool) { await this.flush().catch(() => {}); await this.pool.end(); } }
}
