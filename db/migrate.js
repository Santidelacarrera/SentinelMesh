/* eslint-disable security/detect-non-literal-fs-filename, @typescript-eslint/no-require-imports -- CommonJS script run inside the image; paths come from this repo's own db/ folder */
'use strict';
/**
 * Versioned migrations, runnable inside the production image (plain Node, no ts-node).
 * `schema.sql` is migration 0001 (idempotent baseline); each `migrations/NNNN_*.sql` runs once, in order, inside a transaction and is
 * recorded with its SHA-256 in `schema_migrations` (a changed, already-applied migration is refused).
 * Run with an owner role: DATABASE_ADMIN_URL=postgres://… node db/migrate.js
 */
const { createHash } = require('node:crypto');
const { readdirSync, readFileSync } = require('node:fs');
const { join } = require('node:path');
const { Pool } = require('pg');

(async () => {
  const url = process.env.DATABASE_ADMIN_URL || process.env.DATABASE_URL;
  if (!url) throw new Error('set DATABASE_ADMIN_URL');
  const pool = new Pool({ connectionString: url });
  await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
  const files = [{ version: '0001_baseline', path: join(__dirname, 'schema.sql') },
    ...readdirSync(join(__dirname, 'migrations')).filter((f) => /^\d{4}_.+\.sql$/.test(f)).sort().map((f) => ({ version: f.replace(/\.sql$/, ''), path: join(__dirname, 'migrations', f) }))];
  for (const f of files) {
    const sql = readFileSync(f.path, 'utf8'), sha = createHash('sha256').update(sql).digest('hex');
    const done = (await pool.query('SELECT sha256 FROM schema_migrations WHERE version = $1', [f.version])).rows[0];
    if (done) { if (done.sha256 !== sha && f.version !== '0001_baseline') throw new Error(`migration ${f.version} was modified after being applied`); continue; }
    const c = await pool.connect();
    try { await c.query('BEGIN'); await c.query(sql); await c.query('INSERT INTO schema_migrations (version, sha256) VALUES ($1,$2)', [f.version, sha]); await c.query('COMMIT'); console.log(`applied ${f.version}`); }
    catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
  }
  await pool.end(); console.log('schema up to date');
})().catch((e) => { console.error(e.message); process.exit(1); });
