import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { AuditEntry } from '../store/models';
import { newId, now, stableStringify } from '../common/ids';
import { redact } from '../common/mask';

const GENESIS = '0'.repeat(64);

/** Append-only, hash-chained per organisation. Payloads are redacted *before* hashing/storing. */
@Injectable()
export class AuditTrail {
  private chains = new Map<string, AuditEntry[]>();
  onAppend?: (e: AuditEntry) => void;
  hydrate(entries: AuditEntry[]) { for (const e of entries.sort((a, b) => a.seq - b.seq)) { const c = this.chains.get(e.orgId) ?? []; c.push(Object.freeze(e) as AuditEntry); this.chains.set(e.orgId, c); } }

  append(orgId: string, actor: string, event: string, data: unknown = {}): AuditEntry {
    const chain = this.chains.get(orgId) ?? [];
    const prev = chain.at(-1);
    // JSON round-trip BEFORE hashing: what we hash must be exactly what a store (JSONB included) gives back — undefined keys vanish there.
    const base = { id: newId('aud'), orgId, seq: chain.length + 1, at: now(), actor, event, data: JSON.parse(JSON.stringify(redact(data) ?? null)), prevHash: prev?.hash ?? GENESIS };
    const entry: AuditEntry = { ...base, hash: AuditTrail.hash(base) };
    chain.push(Object.freeze(entry) as AuditEntry);
    this.chains.set(orgId, chain);
    this.onAppend?.(entry);
    return entry;
  }

  list(orgId: string): readonly AuditEntry[] { return [...(this.chains.get(orgId) ?? [])]; }

  verify(orgId: string): { ok: boolean; brokenAt?: number } {
    let prev = GENESIS;
    for (const e of this.chains.get(orgId) ?? []) {
      const { hash, ...base } = e;
      if (e.prevHash !== prev || AuditTrail.hash(base) !== hash) return { ok: false, brokenAt: e.seq };
      prev = hash;
    }
    return { ok: true };
  }

  private static hash(base: Omit<AuditEntry, 'hash'>) {
    return createHash('sha256').update(stableStringify(base)).digest('hex');
  }
}
