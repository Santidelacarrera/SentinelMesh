import { randomUUID, createHash } from 'node:crypto';
export const newId = (prefix: string) => `${prefix}_${randomUUID().replace(/-/g, '').slice(0, 20)}`;
export const sha256 = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
export const now = () => new Date().toISOString();
/** Stable JSON (sorted keys) for hashing / signing. */
export function stableStringify(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  if (v && typeof v === 'object')
    return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${stableStringify((v as any)[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
