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

  append(orgId: string, actor: string, event: string, data: unknown = {}): AuditEntry {
    const chain = this.chains.get(orgId) ?? [];
    const prev = chain.at(-1);
    const base = { id: newId('aud'), orgId, seq: chain.length + 1, at: now(), actor, event, data: redact(data), prevHash: prev?.hash ?? GENESIS };
    const entry: AuditEntry = { ...base, hash: AuditTrail.hash(base) };
    chain.push(Object.freeze(entry) as AuditEntry);
    this.chains.set(orgId, chain);
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
