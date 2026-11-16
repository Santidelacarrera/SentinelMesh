import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { resolveTxt } from 'node:dns/promises';
import { connect as tlsConnect } from 'node:tls';
import { isIP } from 'node:net';
import { Db } from '../store/db';
import { ASSET_TYPES, ExposureFinding, IntelRecord, InventoryAsset, Relation, RelationKind, Vulnerability, Confidence } from '../store/enterprise.models';
import type { Severity } from '../store/models';
import { AuditTrail } from '../audit/audit-trail';
import { Entitlements } from '../platform/entitlements';
import { newId, now, sha256 } from '../common/ids';
import { randomToken } from '../common/crypto';
import { isPrivateIp } from '../common/ssrf';
import { Principal } from '../auth/auth';
import { INTEL_PARSERS, IntelPatch } from './intel';
import { prioritize, PriorityContext } from './priority';
import { analyzeAttackPaths, PathOptions } from './attack-paths';

export const DNS_RESOLVER = Symbol('DNS_RESOLVER'), TLS_PROBE = Symbol('TLS_PROBE');
export type DnsResolver = (name: string) => Promise<string[]>;
export interface TlsResult { authorized: boolean; error?: string; validTo?: string; issuer?: string; subject?: string }
export type TlsProbe = (host: string, port: number) => Promise<TlsResult>;

export const defaultDns: DnsResolver = async (n) => (await resolveTxt(n)).map((c) => c.join(''));
/**
 * Real TLS probe. It INSPECTS the certificate: `rejectUnauthorized:false` is deliberate so an invalid/expired certificate can be
 * reported (we record `authorized` + the error); nothing is sent over the connection and no trust decision depends on it. Refuses loopback/link-local/private targets unless the operator opted in (TLS_PROBE_ALLOW_PRIVATE=1). */
export const defaultTlsProbe: TlsProbe = (host, port) => new Promise((resolve) => {
  if (isIP(host) && isPrivateIp(host) && process.env.TLS_PROBE_ALLOW_PRIVATE !== '1') return resolve({ authorized: false, error: 'private address refused' });
  const s = tlsConnect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: 5000 }, () => {
    const c = s.getPeerCertificate();
    resolve({ authorized: s.authorized, error: s.authorizationError ? String(s.authorizationError) : undefined, validTo: c.valid_to ? new Date(c.valid_to).toISOString() : undefined, issuer: [c.issuer?.O ?? c.issuer?.CN].flat()[0], subject: [c.subject?.CN].flat()[0] });
    s.end();
  });
  s.on('error', (e) => resolve({ authorized: false, error: e.message })); s.on('timeout', () => { resolve({ authorized: false, error: 'timeout' }); s.destroy(); });
});

const isLabel = (l: string) => /^[a-z0-9-]{1,63}$/i.test(l) && !l.startsWith('-') && !l.endsWith('-');
const isHostname = (h: string) => { const p = h.split('.'); return h.length <= 253 && p.length >= 2 && p.every(isLabel) && /^[a-z]{2,63}$/i.test(p[p.length - 1]); };
const SEV = ['critical', 'high', 'medium', 'low', 'info'] as const;
const SLA_DAYS: Record<Severity, number> = { critical: 7, high: 30, medium: 90, low: 180, info: 365 };

export const AssetSchema = z.object({
  type: z.enum(ASSET_TYPES), identifier: z.string().min(1).max(300), name: z.string().min(1).max(200).optional(), criticality: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  owner: z.string().max(200).optional(), internetFacing: z.boolean().optional(), environment: z.enum(['prod', 'staging', 'dev']).optional(),
  tags: z.array(z.string().max(60)).max(30).optional(), controls: z.array(z.string().max(60)).max(30).optional(), source: z.string().min(1).max(100).default('manual'),
}).strict();
export const RelationSchema = z.object({ from: z.string().min(1), to: z.string().min(1), kind: z.enum(['runs_on', 'depends_on', 'hosts', 'trusts', 'member_of', 'authenticates_to', 'stores_data_in', 'can_assume', 'admin_of', 'has_access', 'exposes']), confidence: z.number().min(0).max(1).default(0.8), evidence: z.string().max(500).optional(), source: z.string().max(100).default('manual') }).strict();
export const VulnSchema = z.object({
  assetId: z.string().min(1), cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/i).optional(), cwe: z.string().regex(/^CWE-\d+$/).optional(), title: z.string().min(1).max(300), description: z.string().max(4000).default(''),
  severity: z.enum(SEV).optional(), cvss: z.object({ score: z.number().min(0).max(10), vector: z.string().max(200).optional(), version: z.string().max(10).optional() }).strict().optional(),
  confidence: z.enum(['confirmed', 'suspected', 'unverified']).default('unverified'), evidence: z.array(z.string().max(1000)).max(50).default([]), source: z.string().min(1).max(100),
  owner: z.string().max(200).optional(), dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}/).optional(),
}).strict().refine((v) => v.severity || v.cvss || v.cve, 'provide severity, cvss or a cve (scores are never invented)');
export const ObservationSchema = z.object({ kind: z.enum(['open_port', 'tls_expiring', 'tls_invalid', 'insecure_config', 'forgotten_asset', 'unnecessary_service']), title: z.string().min(1).max(200), detail: z.string().max(1000).default(''), severity: z.enum(SEV).default('medium'), evidence: z.array(z.string().max(1000)).min(1).max(20), confidence: z.enum(['confirmed', 'suspected', 'unverified']).default('suspected') }).strict();
export const ScanResultSchema = z.object({ assetId: z.string().min(1), source: z.string().min(1).max(100), complete: z.boolean().default(false),
  /** Kinds this scan is authoritative for. With `complete: true`, open exposures of these kinds (or of any observed kind) that were not seen again are closed. */
  coverKinds: z.array(ObservationSchema.shape.kind).max(10).default([]), observations: z.array(ObservationSchema).max(500) }).strict();

const norm = (type: string, id: string) => (['domain', 'subdomain', 'ip', 'api', 'web_app'].includes(type) ? id.trim().toLowerCase() : id.trim().toLowerCase());
const addDays = (iso: string, d: number) => new Date(Date.parse(iso) + d * 86400000).toISOString();

@Injectable()
export class CtemService {
  constructor(private db: Db, private audit: AuditTrail, private ent: Entitlements, @Inject(DNS_RESOLVER) private dns: DnsResolver, @Inject(TLS_PROBE) private tls: TlsProbe) {}

  // ═════════ assets ═════════
  async upsertAsset(me: Pick<Principal, 'orgId' | 'userId'>, i: z.infer<typeof AssetSchema>): Promise<{ asset: InventoryAsset; created: boolean }> {
    const identifier = norm(i.type, i.identifier);
    if ((i.type === 'domain' || i.type === 'subdomain') && !isHostname(identifier)) throw new BadRequestException('identifier is not a valid hostname');
    if (i.type === 'ip' && !isIP(identifier)) throw new BadRequestException('identifier is not a valid IP address');
    const t = now(), existing = (await this.db.inventory.where(me.orgId, { type: i.type, identifier }))[0];
    if (existing) {
      const patch: Partial<InventoryAsset> = { lastSeen: t, status: 'active' };
      const changed: string[] = [];
      for (const k of ['criticality', 'owner', 'internetFacing', 'environment'] as const) if (i[k] !== undefined && i[k] !== existing[k]) { (patch as Record<string, unknown>)[k] = i[k]; changed.push(`${k}: ${existing[k]} → ${i[k]}`); }
      if (i.tags) patch.tags = [...new Set([...existing.tags, ...i.tags])];
      if (i.controls) patch.controls = [...new Set([...existing.controls, ...i.controls])];
      const asset = await this.db.inventory.update(me.orgId, existing.id, patch);
      if (existing.status === 'stale') await this.event(me.orgId, asset.id, 'asset_changed', 'asset observed again after being stale');
      if (changed.length) { await this.event(me.orgId, asset.id, 'asset_changed', changed.join('; ')); await this.audit.append(me.orgId, me.userId, 'asset.changed', { assetId: asset.id, changed }); }
      return { asset, created: false };
    }
    await this.ent.assertWithin(me.orgId, 'assets', (await this.db.inventory.list(me.orgId)).length);
    const a: InventoryAsset = { id: newId('ast'), orgId: me.orgId, type: i.type, identifier, name: i.name ?? i.identifier, source: i.source, firstSeen: t, lastSeen: t, status: 'active', criticality: i.criticality ?? 'medium', owner: i.owner,
      internetFacing: i.internetFacing ?? false, environment: i.environment ?? 'prod', tags: i.tags ?? [], controls: i.controls ?? [], ownership: { status: 'unverified' }, inScope: false };
    const { row, created } = await this.db.inventory.createUnique(a, { type: i.type, identifier });
    if (created) { await this.event(me.orgId, row.id, 'asset_discovered', `discovered by ${i.source}`); await this.audit.append(me.orgId, me.userId, 'asset.discovered', { assetId: row.id, type: i.type, identifier, source: i.source }); }
    return { asset: row, created };
  }
  async listAssets(orgId: string, q: Record<string, string | undefined>) {
    const text = q.q?.toLowerCase();
    const all = (await this.db.inventory.list(orgId, (a) => (!q.type || a.type === q.type) && (!q.status || a.status === q.status) && (!q.criticality || a.criticality === q.criticality) && (q.internetFacing === undefined || String(a.internetFacing) === q.internetFacing) && (!text || `${a.name} ${a.identifier} ${a.owner ?? ''}`.toLowerCase().includes(text)))).sort((a, b) => a.name.localeCompare(b.name));
    const limit = Math.min(Number(q.limit ?? 50) || 50, 200), offset = Math.max(Number(q.offset ?? 0) || 0, 0);
    return { total: all.length, items: all.slice(offset, offset + limit) };
  }
  async getAsset(orgId: string, id: string) { const a = await this.db.inventory.get(orgId, id); if (!a) throw new NotFoundException('asset not found'); return a; }
  async assetDetail(orgId: string, id: string) {
    const a = await this.getAsset(orgId, id);
    const [vulns, exposures, rel, events] = await Promise.all([this.db.vulns.where(orgId, { assetId: id }), this.db.exposures.where(orgId, { assetId: id }), this.db.relations.list(orgId, (r) => r.from === id || r.to === id), this.db.exposureEvents.where(orgId, { assetId: id })]);
    return { asset: a, vulnerabilities: vulns, exposures, relations: rel, history: events.sort((x, y) => y.at.localeCompare(x.at)) };
  }
  async relate(me: Principal, i: z.infer<typeof RelationSchema>): Promise<Relation> {
    for (const id of [i.from, i.to]) if (!(await this.db.inventory.get(me.orgId, id)) && !(await this.db.identities.get(me.orgId, id))) throw new NotFoundException(`node ${id} not found`);
    if (i.from === i.to) throw new BadRequestException('a node cannot relate to itself');
    const r: Relation = { id: newId('rel'), orgId: me.orgId, from: i.from, to: i.to, kind: i.kind as RelationKind, source: i.source, confidence: i.confidence, evidence: i.evidence, createdAt: now() };
    const { row, created } = await this.db.relations.createUnique(r, { from: i.from, to: i.to, kind: i.kind });
    if (created) await this.audit.append(me.orgId, me.userId, 'relation.created', { relationId: row.id, from: i.from, to: i.to, kind: i.kind });
    return row;
  }
  async markStale(me: Pick<Principal, 'orgId' | 'userId'>, days = 30) {
    const cut = addDays(now(), -days); let n = 0;
    for (const a of await this.db.inventory.list(me.orgId, (x) => x.status === 'active' && x.lastSeen < cut)) {
      await this.db.inventory.update(me.orgId, a.id, { status: 'stale' }); n++;
      await this.event(me.orgId, a.id, 'asset_stale', `not observed for more than ${days} days`);
      if (a.internetFacing) await this.observe(me, { assetId: a.id, source: 'forgotten-asset-check', complete: false, coverKinds: [], observations: [{ kind: 'forgotten_asset', title: 'Internet-facing asset not observed recently', detail: `last seen ${a.lastSeen}`, severity: 'medium', evidence: [`lastSeen=${a.lastSeen}`, `threshold=${days}d`], confidence: 'confirmed' }] });
    }
    return { markedStale: n };
  }

  // ═════════ ownership & scope ═════════
  async ownershipChallenge(me: Principal, id: string) {
    const a = await this.getAsset(me.orgId, id);
    if (!['domain', 'subdomain'].includes(a.type)) throw new BadRequestException('DNS verification only applies to domains; use manual attestation for other assets');
    const challenge = `sentinelmesh-verify=${randomToken(18)}`;
    await this.db.inventory.update(me.orgId, id, (r) => { r.ownership = { ...r.ownership, challenge }; });
    return { record: `_sentinelmesh.${a.identifier}`, type: 'TXT', value: challenge };
  }
  async verifyOwnership(me: Principal, id: string, method: 'dns_txt' | 'manual_attestation', note?: string) {
    const a = await this.getAsset(me.orgId, id);
    if (method === 'dns_txt') {
      if (!a.ownership.challenge) throw new BadRequestException('request a challenge first');
      const txt = await this.dns(`_sentinelmesh.${a.identifier}`).catch(() => [] as string[]);
      if (!txt.includes(a.ownership.challenge)) throw new BadRequestException('TXT record not found yet (DNS may still be propagating)');
    } else if (!note || note.length < 10) throw new BadRequestException('manual attestation needs a note (at least 10 characters) explaining how ownership was established');
    const out = await this.db.inventory.update(me.orgId, id, (r) => { r.ownership = { status: 'verified', method, verifiedAt: now(), verifiedBy: me.userId }; });
    await this.event(me.orgId, id, 'ownership_verified', `${method}${note ? `: ${note}` : ''}`);
    await this.audit.append(me.orgId, me.userId, 'asset.ownership_verified', { assetId: id, method, note });
    return out;
  }
  async setScope(me: Principal, id: string, inScope: boolean) {
    const a = await this.getAsset(me.orgId, id);
    if (inScope && a.ownership.status !== 'verified') throw new ForbiddenException('only assets with verified ownership can be put in scope for active checks');
    const out = await this.db.inventory.update(me.orgId, id, { inScope });
    await this.audit.append(me.orgId, me.userId, 'asset.scope_changed', { assetId: id, inScope });
    return out;
  }

  // ═════════ intel & vulnerabilities ═════════
  async importIntel(me: Principal, kind: keyof typeof INTEL_PARSERS, payload: unknown) {
    let patches: IntelPatch[];
    try { patches = INTEL_PARSERS[kind](payload); } catch (e) { throw new BadRequestException((e as Error).message); }
    let updated = 0;
    for (const p of patches) {
      const id = `intel:${p.cve}`, ex = await this.db.intel.get(me.orgId, id);
      const rec: IntelRecord = { ...(ex ?? { id, orgId: me.orgId, cve: p.cve, sources: [] }), updatedAt: now() };
      for (const k of ['cvss', 'cwe', 'description', 'kev', 'kevDueDate', 'epss'] as const) if (p[k] !== undefined) (rec as unknown as Record<string, unknown>)[k] = p[k];
      rec.sources = [...new Set([...rec.sources, kind])];
      await this.db.intel.put(rec); updated++;
    }
    await this.audit.append(me.orgId, me.userId, 'intel.imported', { kind, records: updated });
    const reprio = await this.reprioritize(me.orgId, true);
    return { kind, records: updated, vulnerabilitiesReprioritized: reprio.updated };
  }
  intelFor(orgId: string, cve?: string) { return cve ? this.db.intel.get(orgId, `intel:${cve.toUpperCase()}`) : Promise.resolve(undefined); }

  async createVuln(me: Principal, i: z.infer<typeof VulnSchema>): Promise<Vulnerability> {
    const asset = await this.getAsset(me.orgId, i.assetId);
    const cve = i.cve?.toUpperCase(), intel = await this.intelFor(me.orgId, cve), enriched: string[] = [];
    const cvss = i.cvss ?? intel?.cvss; if (!i.cvss && intel?.cvss) enriched.push('cvss');
    const severity: Severity = i.severity ?? (cvss ? (cvss.score >= 9 ? 'critical' : cvss.score >= 7 ? 'high' : cvss.score >= 4 ? 'medium' : cvss.score > 0 ? 'low' : 'info') : 'medium');
    if (!i.severity && !cvss) throw new BadRequestException('severity could not be derived: no CVSS supplied or imported for this CVE (scores are never invented)');
    if (intel?.epss) enriched.push('epss'); if (intel?.kev) enriched.push('kev');
    const fingerprint = sha256(`${asset.id}|${cve ?? i.title}|${i.cwe ?? ''}`);
    const t = now();
    const v: Vulnerability = { id: newId('vul'), orgId: me.orgId, assetId: asset.id, cve, cwe: i.cwe ?? intel?.cwe, title: i.title, description: i.description || intel?.description || '', severity, cvss, epss: intel?.epss, kev: intel?.kev, kevDueDate: intel?.kevDueDate,
      status: 'open', confidence: i.confidence, evidence: i.evidence, source: i.source, detectedAt: t, owner: i.owner ?? asset.owner, dueDate: i.dueDate ?? intel?.kevDueDate ?? addDays(t, SLA_DAYS[severity]).slice(0, 10), fingerprint, enrichedFrom: enriched };
    const { row, created } = await this.db.vulns.createUnique(v, { fingerprint });
    if (!created) return row;                       // same finding reported again: idempotent
    const out = await this.db.vulns.update(me.orgId, row.id, { priority: prioritize(row, await this.contextFor(me.orgId, asset)) });
    await this.audit.append(me.orgId, me.userId, 'vuln.created', { vulnId: row.id, assetId: asset.id, cve, severity, confidence: i.confidence, source: i.source, priority: out.priority?.level });
    return out;
  }
  async setVulnStatus(me: Principal, id: string, status: Vulnerability['status'], note?: string, owner?: string, dueDate?: string) {
    const v = await this.db.vulns.get(me.orgId, id); if (!v) throw new NotFoundException('vulnerability not found');
    if (status === 'accepted' && (!note || note.length < 10)) throw new BadRequestException('accepting a risk requires a justification note (at least 10 characters)');
    const out = await this.db.vulns.update(me.orgId, id, (r) => { r.status = status; if (note) r.statusNote = note; if (owner) r.owner = owner; if (dueDate) r.dueDate = dueDate; if (status === 'resolved') r.resolvedAt = now(); });
    await this.audit.append(me.orgId, me.userId, 'vuln.status_changed', { vulnId: id, from: v.status, to: status, note });
    return out;
  }
  async listVulns(orgId: string, q: Record<string, string | undefined>) {
    const levels = q.priority?.split(','), sev = q.severity?.split(','), text = q.q?.toLowerCase();
    const all = (await this.db.vulns.list(orgId, (v) => (!q.status || q.status.split(',').includes(v.status)) && (!sev || sev.includes(v.severity)) && (!levels || levels.includes(v.priority?.level ?? '')) && (!q.assetId || v.assetId === q.assetId) && (!q.confidence || v.confidence === q.confidence)
      && (q.kev === undefined || String(!!v.kev) === q.kev) && (!text || `${v.title} ${v.cve ?? ''}`.toLowerCase().includes(text)))).sort((a, b) => (b.priority?.score ?? 0) - (a.priority?.score ?? 0));
    const limit = Math.min(Number(q.limit ?? 50) || 50, 200), offset = Math.max(Number(q.offset ?? 0) || 0, 0);
    return { total: all.length, items: all.slice(offset, offset + limit) };
  }
  /** Bridge: scanner findings whose rule id is a CVE become inventory vulnerabilities (confidence "suspected": a scanner said so, nobody verified). */
  async importFromFindings(me: Principal) {
    const assets = await this.db.inventory.list(me.orgId); let created = 0, skipped = 0;
    for (const f of await this.db.findings.list(me.orgId, (x) => x.kind === 'vulnerability' && x.status !== 'resolved' && /^CVE-\d{4}-\d{4,}$/i.test(x.ruleId))) {
      const a = assets.find((x) => x.name.toLowerCase() === f.assetName?.toLowerCase() || x.identifier === f.assetName?.toLowerCase());
      if (!a) { skipped++; continue; }
      const before = (await this.db.vulns.list(me.orgId)).length;
      await this.createVuln(me, { assetId: a.id, cve: f.ruleId, title: f.title, description: f.description, severity: f.baseSeverity, confidence: 'suspected', evidence: [`scanner finding ${f.id}`], source: `scanner-finding` });
      if ((await this.db.vulns.list(me.orgId)).length > before) created++;
    }
    return { created, skippedNoAsset: skipped };
  }

  // ═════════ graph, context, priority ═════════
  private async graph(orgId: string) {
    const [assets, identities, relations, vulns, exposures, signals] = await Promise.all([this.db.inventory.list(orgId), this.db.identities.list(orgId), this.db.relations.list(orgId), this.db.vulns.list(orgId), this.db.exposures.list(orgId), this.db.signals.list(orgId, (s) => !!(s.assetId || s.identityId))]);
    return { assets, identities, relations, vulns, exposures, signals };
  }
  async contextFor(orgId: string, asset: InventoryAsset): Promise<PriorityContext> {
    return this.contextFrom(await this.graph(orgId), asset);
  }
  /** Blast radius of compromising `asset`: privileged identities and critical assets reachable downstream (depth ≤ 3) through recorded relations. */
  private contextFrom(g: Awaited<ReturnType<CtemService['graph']>>, asset: InventoryAsset): PriorityContext {
    const privIds = new Set(g.identities.filter((i) => i.privileged && i.status === 'active').map((i) => i.id));
    const crit = new Set(g.assets.filter((a) => a.criticality === 'critical' && a.id !== asset.id).map((a) => a.id));
    const edges: Array<[string, string]> = g.relations.map((r) => (r.kind === 'runs_on' ? [r.to, r.from] : [r.from, r.to]));
    for (const i of g.identities) for (const a of i.assetIds) edges.push([i.id, a]);
    const seen = new Set([asset.id]); let frontier = [asset.id], priv = 0, found = 0;
    for (let d = 0; d < 3 && frontier.length; d++) {
      const next: string[] = [];
      for (const n of frontier) for (const [f, t] of edges) if (f === n && !seen.has(t)) { seen.add(t); next.push(t); if (crit.has(t)) found++; if (privIds.has(t)) priv++; }
      frontier = next;
    }
    return { asset, privilegedIdentities: priv, criticalDependents: found, openExposures: g.exposures.filter((e) => e.assetId === asset.id && e.status === 'open' && e.confidence === 'confirmed').length };
  }
  async reprioritize(orgId: string, refreshIntel = false) {
    const g = await this.graph(orgId), byId = new Map(g.assets.map((a) => [a.id, a])); let updated = 0;
    for (const v of g.vulns.filter((x) => x.status !== 'resolved')) {
      let cur = v;
      if (refreshIntel && v.cve) {
        const intel = await this.intelFor(orgId, v.cve);
        if (intel) { cur = { ...v, cvss: v.cvss ?? intel.cvss, epss: intel.epss ?? v.epss, kev: intel.kev ?? v.kev, kevDueDate: intel.kevDueDate ?? v.kevDueDate, cwe: v.cwe ?? intel.cwe, enrichedFrom: [...new Set([...(v.enrichedFrom ?? []), ...(intel.cvss ? ['cvss'] : []), ...(intel.epss ? ['epss'] : []), ...(intel.kev ? ['kev'] : [])])] }; }
      }
      const a = byId.get(v.assetId), priority = prioritize(cur, a ? this.contextFrom(g, a) : {});
      if (JSON.stringify([cur.cvss, cur.epss, cur.kev, cur.kevDueDate, priority.score]) !== JSON.stringify([v.cvss, v.epss, v.kev, v.kevDueDate, v.priority?.score])) {
        await this.db.vulns.update(orgId, v.id, (r) => { Object.assign(r, { cvss: cur.cvss, epss: cur.epss, kev: cur.kev, kevDueDate: cur.kevDueDate, cwe: cur.cwe, enrichedFrom: cur.enrichedFrom, priority }); if (cur.kevDueDate && (!r.dueDate || r.dueDate > cur.kevDueDate)) r.dueDate = cur.kevDueDate; });
        updated++;
      }
    }
    return { updated };
  }
  async priorities(orgId: string) {
    const { items } = await this.listVulns(orgId, { status: 'open,in_progress', limit: '200' });
    const now0 = Date.now();
    return items.map((v) => ({ id: v.id, assetId: v.assetId, title: v.title, cve: v.cve, confidence: v.confidence, kev: !!v.kev, dueDate: v.dueDate, overdue: !!v.dueDate && Date.parse(v.dueDate) < now0, priority: v.priority }));
  }
  async attackPaths(orgId: string, o: PathOptions) { return analyzeAttackPaths(await this.graph(orgId), o); }

  // ═════════ attack surface ═════════
  private event(orgId: string, assetId: string | undefined, type: Parameters<Db['exposureEvents']['put']>[0]['type'], detail: string) {
    return this.db.exposureEvents.put({ id: newId('evt'), orgId, assetId, at: now(), type, detail });
  }
  /**
   * Records what an AUTHORISED scanner/connector saw. First sighting stays "suspected"; a second sighting (or a confirmed observation) promotes it.
   * With `complete: true`, open exposures of the reported kinds that were NOT seen again are closed (the history keeps both events).
   */
  async observe(me: Pick<Principal, 'orgId' | 'userId'>, i: z.infer<typeof ScanResultSchema>) {
    const asset = await this.getAsset(me.orgId, i.assetId);
    if (asset.status === 'retired') throw new BadRequestException('asset is retired');
    let opened = 0, confirmed = 0, resolved = 0; const seenFp = new Set<string>(), kinds = new Set<string>(i.coverKinds);
    for (const o of i.observations) {
      kinds.add(o.kind);
      const fingerprint = sha256(`${asset.id}|${o.kind}|${o.title.toLowerCase()}`); seenFp.add(fingerprint);
      const t = now(), e: ExposureFinding = { id: newId('exp'), orgId: me.orgId, assetId: asset.id, kind: o.kind, title: o.title, detail: o.detail, severity: o.severity, evidence: o.evidence, confidence: o.confidence, status: 'open', firstSeen: t, lastSeen: t, fingerprint, seen: 1, source: i.source };
      const { row, created } = await this.db.exposures.createUnique(e, { fingerprint, status: 'open' });
      if (created) { opened++; await this.event(me.orgId, asset.id, 'exposure_opened', `${o.kind}: ${o.title} (${o.confidence})`); continue; }
      const out = await this.db.exposures.update(me.orgId, row.id, (r) => { r.seen++; r.lastSeen = t; r.evidence = [...new Set([...r.evidence, ...o.evidence])].slice(-30); if (r.confidence !== 'confirmed' && (r.seen >= 2 || o.confidence === 'confirmed')) r.confidence = 'confirmed'; });
      if (row.confidence !== 'confirmed' && out.confidence === 'confirmed') confirmed++;
    }
    if (i.complete) for (const x of await this.db.exposures.where(me.orgId, { assetId: asset.id, status: 'open' })) {
      if (kinds.has(x.kind) && !seenFp.has(x.fingerprint)) { await this.db.exposures.update(me.orgId, x.id, { status: 'resolved', resolvedAt: now() }); resolved++; await this.event(me.orgId, asset.id, 'exposure_resolved', `${x.kind}: ${x.title} no longer observed`); }
    }
    await this.audit.append(me.orgId, me.userId, 'exposure.observed', { assetId: asset.id, source: i.source, opened, confirmed, resolved });
    return { opened, confirmed, resolved };
  }
  async tlsCheck(me: Principal, id: string, port = 443) {
    const a = await this.getAsset(me.orgId, id);
    if (a.ownership.status !== 'verified' || !a.inScope) throw new ForbiddenException('active checks are only allowed on assets with verified ownership that are explicitly in scope');
    if (!['domain', 'subdomain', 'web_app', 'api', 'server', 'ip'].includes(a.type)) throw new BadRequestException('TLS checks do not apply to this asset type');
    const host = a.identifier.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const r = await this.tls(host, port);
    await this.audit.append(me.orgId, me.userId, 'asset.tls_checked', { assetId: id, host, port, authorized: r.authorized, validTo: r.validTo });
    const obs: z.infer<typeof ObservationSchema>[] = [];
    if (r.validTo) { const days = Math.floor((Date.parse(r.validTo) - Date.now()) / 86400000); if (days < 30) obs.push({ kind: 'tls_expiring', title: `TLS certificate on port ${port} ${days < 0 ? 'has expired' : `expires in ${days} days`}`, detail: `valid until ${r.validTo}`, severity: days < 0 ? 'high' : days < 7 ? 'high' : 'medium', evidence: [`notAfter=${r.validTo}`, `issuer=${r.issuer ?? 'unknown'}`], confidence: 'confirmed' }); }
    if (!r.authorized) obs.push({ kind: 'tls_invalid', title: `TLS certificate on port ${port} is not trusted`, detail: r.error ?? 'validation failed', severity: 'medium', evidence: [`error=${r.error ?? 'unknown'}`], confidence: r.error === 'timeout' || r.error?.includes('refused') ? 'unverified' : 'suspected' });
    const res = await this.observe(me, { assetId: id, source: 'tls-check', complete: true, coverKinds: ['tls_expiring', 'tls_invalid'], observations: obs });
    return { result: r, ...res };
  }
  async listExposures(orgId: string, q: Record<string, string | undefined>) {
    const all = (await this.db.exposures.list(orgId, (e) => (!q.status || e.status === q.status) && (!q.assetId || e.assetId === q.assetId) && (!q.kind || e.kind === q.kind) && (!q.confidence || e.confidence === (q.confidence as Confidence)))).sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
    const limit = Math.min(Number(q.limit ?? 50) || 50, 200), offset = Math.max(Number(q.offset ?? 0) || 0, 0);
    return { total: all.length, items: all.slice(offset, offset + limit) };
  }
  async history(orgId: string, assetId?: string) { return (await this.db.exposureEvents.list(orgId, (e) => !assetId || e.assetId === assetId)).sort((a, b) => b.at.localeCompare(a.at)).slice(0, 500); }
}
