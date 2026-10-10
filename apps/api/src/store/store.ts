/**
 * Org-scoped async repositories. Every call takes an orgId, so a handler physically cannot touch another tenant's rows.
 * Two implementations behind one contract: MemoryRepo (tests/dev) and PgRepo (PostgreSQL with RLS; safe with N API replicas).
 */
export interface Row { id: string; orgId: string }

export class UniqueConflict extends Error {}

export interface Repo<T extends Row> {
  /** Upsert by id. */
  put(row: T): Promise<T>;
  get(orgId: string, id: string): Promise<T | undefined>;
  /** Full org scan filtered in process. Prefer `where` on hot paths. */
  list(orgId: string, pred?: (r: T) => boolean): Promise<T[]>;
  /** Equality match on top-level document fields (Postgres: JSONB containment, indexable). */
  where(orgId: string, match: Partial<Record<string, unknown>>): Promise<T[]>;
  /**
   * Atomic read-modify-write. `fn` may mutate the row or throw to abort (nothing is written). Concurrent updaters of the same
   * row are serialised (Postgres: SELECT … FOR UPDATE), so a guard inside `fn` is race-free across replicas.
   */
  update(orgId: string, id: string, fn: Partial<T> | ((r: T) => void)): Promise<T>;
  /** Insert unless a row matching `unique` already exists; returns whichever row is stored and whether this call created it. */
  createUnique(row: T, unique: Partial<Record<string, unknown>>): Promise<{ row: T; created: boolean }>;
}

const matches = (r: object, m: Partial<Record<string, unknown>>) => Object.entries(m).every(([k, v]) => (r as Record<string, unknown>)[k] === v);

export class MemoryRepo<T extends Row> implements Repo<T> {
  private rows = new Map<string, T>();
  async put(row: T) { this.rows.set(row.id, structuredClone(row)); return row; }
  async get(orgId: string, id: string) { const r = this.rows.get(id); return r && r.orgId === orgId ? structuredClone(r) : undefined; }
  async list(orgId: string, pred: (r: T) => boolean = () => true) { return [...this.rows.values()].filter((r) => r.orgId === orgId && pred(r)).map((r) => structuredClone(r)); }
  async where(orgId: string, m: Partial<Record<string, unknown>>) { return this.list(orgId, (r) => matches(r, m)); }
  async update(orgId: string, id: string, fn: Partial<T> | ((r: T) => void)) {
    const cur = this.rows.get(id);
    if (!cur || cur.orgId !== orgId) throw new Error(`not found: ${id}`);
    const draft = structuredClone(cur);               // throw inside fn ⇒ nothing is applied (same as a rolled-back transaction)
    if (typeof fn === 'function') fn(draft); else Object.assign(draft, fn);
    this.rows.set(id, draft);
    return structuredClone(draft);
  }
  async createUnique(row: T, unique: Partial<Record<string, unknown>>) {
    // check-and-insert with no await in between ⇒ atomic on the single-threaded event loop
    const hit = [...this.rows.values()].find((r) => r.orgId === row.orgId && matches(r, unique));
    if (hit) return { row: structuredClone(hit), created: false };
    this.rows.set(row.id, structuredClone(row));
    return { row, created: true };
  }
}
