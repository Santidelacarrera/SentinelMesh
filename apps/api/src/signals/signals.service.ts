import { Injectable, Logger } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { Signal } from '../store/enterprise.models';
import { AuditTrail } from '../audit/audit-trail';
import { newId, now, sha256 } from '../common/ids';
import { redact } from '../common/mask';
import { EventBus } from '../common/events';
import { Entitlements } from '../platform/entitlements';
import type { SignalInput } from '../connectors/types';

export const SignalSchema = z.object({
  source: z.string().min(1).max(60), sourceId: z.string().min(1).max(300), kind: z.enum(['alert', 'detection', 'incident', 'event']).default('alert'), title: z.string().min(1).max(300),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']), at: z.string().datetime().default(() => new Date().toISOString()), host: z.string().max(253).optional(), ip: z.string().max(45).optional(), user: z.string().max(254).optional(),
  cves: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/i)).max(50).default([]), domains: z.array(z.string().max(253)).max(50).default([]), ips: z.array(z.string().max(45)).max(50).default([]), raw: z.unknown().optional(),
}).strict();

export type SignalListener = (orgId: string, created: Signal[]) => Promise<void>;

/** Normalises events from any source into `Signal`s: dedupes by (source, sourceId), resolves asset/identity links, redacts the raw payload. */
@Injectable()
export class SignalsService {
  private log = new Logger('Signals');
  private listeners: SignalListener[] = [];
    private quota = new Map<string, number>();   // events accepted today per organisation, per replica (a soft limit; the plan figure is a placeholder)
  constructor(private db: Db, private audit: AuditTrail, private bus: EventBus, private ent: Entitlements) {}
  onCreated(l: SignalListener) { this.listeners.push(l); }

  async ingest(orgId: string, actor: string, inputs: SignalInput[]): Promise<{ created: number; duplicates: number; signals: Signal[] }> {
    const day = new Date().toISOString().slice(0, 10), qk = `${orgId}:${day}`;
    for (const k of this.quota.keys()) if (!k.endsWith(day)) this.quota.delete(k);
    await this.ent.assertWithin(orgId, 'eventsPerDay', this.quota.get(qk) ?? 0);
    const [assets, identities] = await Promise.all([this.db.inventory.list(orgId), this.db.identities.list(orgId)]);
    const byHost = new Map<string, string>(), byIp = new Map<string, string>(), byUser = new Map<string, string>();
    for (const a of assets) { byHost.set(a.identifier.toLowerCase(), a.id); byHost.set(a.name.toLowerCase(), a.id); if (a.type === 'ip') byIp.set(a.identifier, a.id); for (const t of a.tags) { const m = /^public-ip:(.+)$/.exec(t); if (m) byIp.set(m[1], a.id); } }
    for (const i of identities) { byUser.set(i.name.toLowerCase(), i.id); if (i.email) byUser.set(i.email.toLowerCase(), i.id); byUser.set(i.externalId.toLowerCase(), i.id); }
    const created: Signal[] = []; let dup = 0;
    for (const s of inputs) {
      const host = s.host?.toLowerCase(), user = s.user?.toLowerCase();
      const sig: Signal = { id: newId('sig'), orgId, source: s.source, sourceId: s.sourceId, dedupKey: sha256(`${s.source}|${s.sourceId}`), kind: s.kind, title: s.title.slice(0, 300), severity: s.severity, at: s.at, host, ip: s.ip, user: s.user,
        assetId: (host && (byHost.get(host) ?? byHost.get(host.split('.')[0]))) || (s.ip && byIp.get(s.ip)) || undefined, identityId: (user && byUser.get(user)) || undefined,
        cves: [...new Set((s.cves ?? []).map((c) => c.toUpperCase()))], domains: s.domains ?? [], ips: [...new Set([...(s.ips ?? []), ...(s.ip ? [s.ip] : [])])], raw: s.raw === undefined ? undefined : redact(s.raw), createdAt: now() };
      const { row, created: isNew } = await this.db.signals.createUnique(sig, { dedupKey: sig.dedupKey });
      if (isNew) created.push(row); else dup++;
    }
    this.quota.set(qk, (this.quota.get(qk) ?? 0) + created.length);
    if (created.length) {
      await this.audit.append(orgId, actor, 'signals.ingested', { count: created.length, duplicates: dup, sources: [...new Set(created.map((c) => c.source))] });
      for (const l of this.listeners) await l(orgId, created).catch((e) => this.log.error(`signal listener failed: ${(e as Error).message}`));
      for (const s of created) { const a = s.assetId ? await this.db.inventory.get(orgId, s.assetId) : undefined; await this.bus.emit({ type: 'signal', orgId, actor, entity: { ...s, assetName: a?.name } }); }
    }
    return { created: created.length, duplicates: dup, signals: created };
  }

  async list(orgId: string, q: Record<string, string | undefined>) {
    const all = (await this.db.signals.list(orgId, (s) => (!q.source || s.source === q.source) && (!q.severity || q.severity.split(',').includes(s.severity)) && (!q.assetId || s.assetId === q.assetId) && (!q.correlated || String(!!s.correlationId) === q.correlated))).sort((a, b) => b.at.localeCompare(a.at));
    const limit = Math.min(Number(q.limit ?? 50) || 50, 200), offset = Math.max(Number(q.offset ?? 0) || 0, 0);
    return { total: all.length, items: all.slice(offset, offset + limit) };
  }
}
