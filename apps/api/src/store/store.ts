/**
 * Org-scoped storage. Every read/write takes an orgId, so a handler physically cannot
 * touch another tenant's rows. Postgres equivalent: db/schema.sql (RLS keyed on app.org_id).
 */
export class Collection<T extends { id: string; orgId: string }> {
  private rows = new Map<string, T>();
  put(row: T): T { this.rows.set(row.id, structuredClone(row)); return row; }
  get(orgId: string, id: string): T | undefined {
    const r = this.rows.get(id);
    return r && r.orgId === orgId ? structuredClone(r) : undefined;
  }
  list(orgId: string, pred: (r: T) => boolean = () => true): T[] {
    return [...this.rows.values()].filter((r) => r.orgId === orgId && pred(r)).map((r) => structuredClone(r));
  }
  update(orgId: string, id: string, patch: Partial<T> | ((r: T) => void)): T {
    const cur = this.rows.get(id);
    if (!cur || cur.orgId !== orgId) throw new Error(`not found: ${id}`);
    if (typeof patch === 'function') patch(cur); else Object.assign(cur, patch);
    return structuredClone(cur);
  }
}
