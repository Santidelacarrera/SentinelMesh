import { Injectable, Logger, OnApplicationShutdown, OnModuleInit } from '@nestjs/common';
import { Pool, PoolClient } from 'pg';
import { Db, TABLES } from './db';
import { AuditTrail, AuditStore } from '../audit/audit-trail';
import { AuditEntry } from './models';
import { Repo, Row, UniqueConflict } from './store';

/** Runs `fn` in a transaction with `app.org_id` set, so PostgreSQL row-level security applies to every statement. */
export class PgTx {
  constructor(public pool: Pool) {}
  async run<T>(orgId: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query("SELECT set_config('app.org_id', $1, true)", [orgId]);
      const r = await fn(c); await c.query('COMMIT'); return r;
    } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
  }
}

const UNIQUE_VIOLATION = '23505';

export class PgRepo<T extends Row> implements Repo<T> {
  constructor(private tx: PgTx, private table: string) {}
  private ensureOrg = (c: PoolClient, orgId: string) => c.query('INSERT INTO organization (id) VALUES ($1) ON CONFLICT DO NOTHING', [orgId]);
  private conflict() { return this.table === 'security_workflow' ? 'DO NOTHING' : 'DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()'; }

  async put(row: T) {
    await this.tx.run(row.orgId, async (c) => {
      await this.ensureOrg(c, row.orgId);
      await c.query(`INSERT INTO ${this.table} (id, org_id, doc) VALUES ($1, $2, $3) ON CONFLICT (id) ${this.conflict()}`, [row.id, row.orgId, JSON.stringify(row)]);
    });
    return row;
  }
  async get(orgId: string, id: string) {
    return this.tx.run(orgId, async (c) => (await c.query(`SELECT doc FROM ${this.table} WHERE id = $1 AND org_id = $2`, [id, orgId])).rows[0]?.doc as T | undefined);
  }
  async list(orgId: string, pred: (r: T) => boolean = () => true) {
    const rows = await this.tx.run(orgId, async (c) => (await c.query(`SELECT doc FROM ${this.table} WHERE org_id = $1 ORDER BY updated_at DESC`, [orgId])).rows.map((r) => r.doc as T));
    return rows.filter(pred);
  }
  async where(orgId: string, match: Partial<Record<string, unknown>>) {
    return this.tx.run(orgId, async (c) => (await c.query(`SELECT doc FROM ${this.table} WHERE org_id = $1 AND doc @> $2::jsonb`, [orgId, JSON.stringify(match)])).rows.map((r) => r.doc as T));
  }
  async update(orgId: string, id: string, fn: Partial<T> | ((r: T) => void)) {
    return this.tx.run(orgId, async (c) => {
      const cur = (await c.query(`SELECT doc FROM ${this.table} WHERE id = $1 AND org_id = $2 FOR UPDATE`, [id, orgId])).rows[0]?.doc as T | undefined;
      if (!cur) throw new Error(`not found: ${id}`);
      if (typeof fn === 'function') fn(cur); else Object.assign(cur, fn);   // a throw rolls the transaction back
      await c.query(`UPDATE ${this.table} SET doc = $1, updated_at = now() WHERE id = $2 AND org_id = $3`, [JSON.stringify(cur), id, orgId]);
      return cur;
    });
  }
  async createUnique(row: T, unique: Partial<Record<string, unknown>>) {
    try {
      return await this.tx.run(row.orgId, async (c) => {
        await this.ensureOrg(c, row.orgId);
        const hit = (await c.query(`SELECT doc FROM ${this.table} WHERE org_id = $1 AND doc @> $2::jsonb LIMIT 1`, [row.orgId, JSON.stringify(unique)])).rows[0]?.doc as T | undefined;
        if (hit) return { row: hit, created: false };
        await c.query(`INSERT INTO ${this.table} (id, org_id, doc) VALUES ($1, $2, $3)`, [row.id, row.orgId, JSON.stringify(row)]);
        return { row, created: true };
      });
    } catch (e) {
      // Two replicas raced past the SELECT: the DB unique index decides; the loser reads the winner's row.
      if ((e as { code?: string }).code !== UNIQUE_VIOLATION) throw e;
      const hit = (await this.where(row.orgId, unique))[0];
      if (!hit) throw new UniqueConflict((e as Error).message);
      return { row: hit, created: false };
    }
  }
}

/** Hash-chained audit log in PostgreSQL. A per-org advisory lock serialises appends across replicas so `seq`/`prevHash` never fork. */
export class PgAuditStore implements AuditStore {
  constructor(private tx: PgTx) {}
  async append(orgId: string, build: (prev: AuditEntry | undefined) => AuditEntry) {
    return this.tx.run(orgId, async (c) => {
      await c.query('INSERT INTO organization (id) VALUES ($1) ON CONFLICT DO NOTHING', [orgId]);
      await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`audit:${orgId}`]);
      const last = (await c.query('SELECT * FROM audit_trail WHERE org_id = $1 ORDER BY seq DESC LIMIT 1', [orgId])).rows[0];
      const e = build(last && rowToEntry(last));
      await c.query('INSERT INTO audit_trail (id, org_id, seq, at, actor, event, data, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [e.id, e.orgId, e.seq, e.at, e.actor, e.event, JSON.stringify(e.data), e.prevHash, e.hash]);
      return e;
    });
  }
  async list(orgId: string) {
    return this.tx.run(orgId, async (c) => (await c.query('SELECT * FROM audit_trail WHERE org_id = $1 ORDER BY seq', [orgId])).rows.map(rowToEntry));
  }
}
const rowToEntry = (r: any): AuditEntry => ({ id: r.id, orgId: r.org_id, seq: Number(r.seq), at: new Date(r.at).toISOString(), actor: r.actor, event: r.event, data: r.data, prevHash: r.prev_hash, hash: r.hash });

/** With DATABASE_URL every repository (and the audit store) is PostgreSQL-backed. Nothing is cached in process: N replicas see the same state. */
@Injectable()
export class PgBackend implements OnModuleInit, OnApplicationShutdown {
  private log = new Logger('Pg');
  pool?: Pool;
  constructor(private db: Db, private audit: AuditTrail) {}
  async onModuleInit() {
    const url = process.env.DATABASE_URL; if (!url) return;
    this.pool = new Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 10) });
    const tx = new PgTx(this.pool);
    for (const [k, table] of Object.entries(TABLES) as Array<[keyof Db, string]>) (this.db as unknown as Record<string, Repo<Row>>)[k] = new PgRepo(tx, table);
    this.audit.useStore(new PgAuditStore(tx));
    this.log.log('PostgreSQL repositories active (stateless API)');
  }
  async onApplicationShutdown() { await this.pool?.end(); }
}
