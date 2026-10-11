import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { AuditEntry } from '../store/models';
import { newId, now, stableStringify } from '../common/ids';
import { redact } from '../common/mask';
import { currentCorrelation } from '../common/correlation';

const GENESIS = '0'.repeat(64);

/** Storage for the chain. `append` must make "read last entry → build next → write" atomic per organisation. */
export interface AuditStore {
  append(orgId: string, build: (prev: AuditEntry | undefined) => AuditEntry): Promise<AuditEntry>;
  list(orgId: string): Promise<AuditEntry[]>;
}

export class MemoryAuditStore implements AuditStore {
  private chains = new Map<string, AuditEntry[]>();
  private tails = new Map<string, Promise<unknown>>();
  async append(orgId: string, build: (prev: AuditEntry | undefined) => AuditEntry) {
    const run = (this.tails.get(orgId) ?? Promise.resolve()).then(() => {
      const chain = this.chains.get(orgId) ?? [];
      const e = Object.freeze(build(chain.at(-1))) as AuditEntry;
      chain.push(e); this.chains.set(orgId, chain); return e;
    });
    this.tails.set(orgId, run.catch(() => {}));
    return run;
  }
  async list(orgId: string) { return [...(this.chains.get(orgId) ?? [])]; }
  /** test helper: simulate someone tampering with storage */
  _tamper(orgId: string, i: number, patch: Partial<AuditEntry>) { const c = this.chains.get(orgId)!; c[i] = { ...c[i], ...patch }; }
}

/** Append-only, hash-chained per organisation. Payloads are redacted *before* hashing/storing. */
@Injectable()
export class AuditTrail {
  private store: AuditStore = new MemoryAuditStore();
  useStore(s: AuditStore) { this.store = s; }
  get memory() { return this.store as MemoryAuditStore; }

  append(orgId: string, actor: string, event: string, data: unknown = {}): Promise<AuditEntry> {
    // JSON round-trip first: what we hash must be exactly what any store (JSONB included) will give back (undefined keys vanish).
    const rid = currentCorrelation()?.requestId;
    const safe = JSON.parse(JSON.stringify(redact(rid && data && typeof data === 'object' && !Array.isArray(data) ? { ...(data as object), requestId: rid } : data)));
    return this.store.append(orgId, (prev) => {
      const base = { id: newId('aud'), orgId, seq: (prev?.seq ?? 0) + 1, at: now(), actor, event, data: safe, prevHash: prev?.hash ?? GENESIS };
      return { ...base, hash: AuditTrail.hash(base) };
    });
  }

  list(orgId: string): Promise<AuditEntry[]> { return this.store.list(orgId); }

  async verify(orgId: string): Promise<{ ok: boolean; brokenAt?: number }> {
    let prev = GENESIS;
    for (const e of await this.store.list(orgId)) {
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
