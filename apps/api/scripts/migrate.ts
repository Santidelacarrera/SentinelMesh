import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Pool } from 'pg';
/** Applies db/schema.sql (idempotent). Use an owner/admin DATABASE_ADMIN_URL; the app itself runs as a NOBYPASSRLS role. */
(async () => {
  const url = process.env.DATABASE_ADMIN_URL ?? process.env.DATABASE_URL; if (!url) throw new Error('set DATABASE_ADMIN_URL');
  const pool = new Pool({ connectionString: url });
  await pool.query(readFileSync(join(__dirname, '../../../db/schema.sql'), 'utf8'));
  await pool.end(); console.log('schema applied');
})().catch((e) => { console.error(e.message); process.exit(1); });
