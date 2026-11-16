import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Pool } from 'pg';
/**
 * Versioned migrations. `db/schema.sql` is migration 0001 (baseline, idempotent); every `db/migrations/NNNN_*.sql` runs once, in order,
 * and is recorded in `schema_migrations` with its SHA-256 (a changed, already-applied migration is refused).
 * Use an owner/admin DATABASE_ADMIN_URL; the app itself runs as a NOBYPASSRLS role.
 */
(async () => {
  const url = process.env.DATABASE_ADMIN_URL ?? process.env.DATABASE_URL; if (!url) throw new Error('set DATABASE_ADMIN_URL');
  const root = join(__dirname, '../../../db');
  const pool = new Pool({ connectionString: url });
  await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
  const files = [{ version: '0001_baseline', path: join(root, 'schema.sql') },
    ...readdirSync(join(root, 'migrations')).filter((f) => /^\d{4}_.+\.sql$/.test(f)).sort().map((f) => ({ version: f.replace(/\.sql$/, ''), path: join(root, 'migrations', f) }))];
  for (const f of files) {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- paths come from readdirSync of the repo's own db/ folder
    const sql = readFileSync(f.path, 'utf8'), sha = createHash('sha256').update(sql).digest('hex');
    const done = (await pool.query('SELECT sha256 FROM schema_migrations WHERE version = $1', [f.version])).rows[0];
    if (done) { if (done.sha256 !== sha && f.version !== '0001_baseline') throw new Error(`migration ${f.version} was modified after being applied`); continue; }
    const c = await pool.connect();
    try { await c.query('BEGIN'); await c.query(sql); await c.query('INSERT INTO schema_migrations (version, sha256) VALUES ($1,$2)', [f.version, sha]); await c.query('COMMIT'); console.log(`applied ${f.version}`); }
    catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
  }
  await pool.end(); console.log('schema up to date');
})().catch((e) => { console.error(e.message); process.exit(1); });
