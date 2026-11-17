import { Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Db } from '../store/db';
import { Correlation, CorrelationReason, Signal, Vulnerability } from '../store/enterprise.models';
import type { Severity } from '../store/models';
import { AuditTrail } from '../audit/audit-trail';
import { SignalsService } from '../signals/signals.service';
import { CasesService } from './cases.service';
import { newId, now } from '../common/ids';
import { Principal } from '../auth/auth';

const SEV_POINTS: Record<Severity, number> = { critical: 70, high: 55, medium: 35, low: 15, info: 5 };
const WINDOW_MS = () => Number(process.env.CORRELATION_WINDOW_SEC ?? 1800) * 1000;
const AUTO_CASE_RISK = () => Number(process.env.CORRELATION_AUTO_CASE_RISK ?? 60);
const WEIGHT = { asset: 0.8, identity: 0.7, vulnerability: 0.85, ip: 0.6, domain: 0.5 } as const;
const PRIVATE_IP = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/;

/**
 * Groups signals from different sources into one correlation. Every link records WHY (asset, identity, IP, domain, vulnerability, time) and from
 * which source, with a confidence; the combined confidence is a noisy-OR over the strongest reason of each type. A correlation is a hypothesis:
 * it stays `probable` until a human confirms it, and it can be dismissed.
 */
@Injectable()
export class CorrelationService implements OnModuleInit {
  constructor(private db: Db, private audit: AuditTrail, private signals: SignalsService, private cases: CasesService) {}
  onModuleInit() { this.signals.onCreated((orgId, created) => this.correlate(orgId, created).then(() => undefined)); }

  /** Reasons two signals are related, strongest per type. Shared PRIVATE IPs are not evidence (everyone shares 10.x). */
  static reasons(a: Signal, b: Signal, vulnOnAsset?: Vulnerability): CorrelationReason[] {
    const r: CorrelationReason[] = [], src = `${a.source}+${b.source}`;
    if (a.assetId && a.assetId === b.assetId) r.push({ type: 'asset', value: a.assetId, confidence: WEIGHT.asset, source: src });
    if (a.identityId && a.identityId === b.identityId) r.push({ type: 'identity', value: a.identityId, confidence: WEIGHT.identity, source: src });
    const ips = a.ips.filter((i) => b.ips.includes(i) && !PRIVATE_IP.test(i)); if (ips.length) r.push({ type: 'ip', value: ips[0], confidence: WEIGHT.ip, source: src });
    const doms = a.domains.filter((d) => b.domains.includes(d)); if (doms.length) r.push({ type: 'domain', value: doms[0], confidence: WEIGHT.domain, source: src });
    const cves = a.cves.filter((c) => b.cves.includes(c)); if (cves.length) r.push({ type: 'vulnerability', value: cves[0], confidence: vulnOnAsset ? WEIGHT.vulnerability : 0.5, source: vulnOnAsset ? `${src}+inventory` : src });
    return r;
  }
  static combine(reasons: CorrelationReason[]): number {
    const best = new Map<string, number>(); for (const r of reasons) if (r.type !== 'time') best.set(r.type, Math.max(best.get(r.type) ?? 0, r.confidence));
    return Math.round((1 - [...best.values()].reduce((p, c) => p * (1 - c), 1)) * 1000) / 1000;
  }

  /** Shared-attribute keys of a signal: two signals can only be related if they share at least one. */
  private static keys(s: Signal): string[] {
    return [...(s.assetId ? [`a:${s.assetId}`] : []), ...(s.identityId ? [`i:${s.identityId}`] : []), ...s.ips.filter((i) => !PRIVATE_IP.test(i)).map((i) => `p:${i}`), ...s.domains.map((d) => `d:${d}`), ...s.cves.map((c) => `c:${c}`)];
  }

  /** Loads the organisation's signals once and indexes them by shared attribute, so a batch costs O(batch × matches) instead of a full scan per signal. */
  async correlate(orgId: string, fresh: Signal[]) {
    const out: Correlation[] = [], win = WINDOW_MS();
    const all = new Map((await this.db.signals.list(orgId)).map((x) => [x.id, x])), index = new Map<string, Set<string>>();
    for (const x of all.values()) for (const k of CorrelationService.keys(x)) (index.get(k) ?? index.set(k, new Set()).get(k)!).add(x.id);
    for (const s of fresh) {
      const cur = all.get(s.id) ?? s;
      if (cur.correlationId) continue;
      const ids = new Set<string>(); for (const k of CorrelationService.keys(cur)) for (const id of index.get(k) ?? []) ids.add(id);
      const near = [...ids].filter((id) => id !== cur.id).map((id) => all.get(id)!).filter((x) => Math.abs(Date.parse(x.at) - Date.parse(cur.at)) <= win);
      const links = near.map((x) => ({ x, why: CorrelationService.reasons(cur, x) })).filter((l) => l.why.length);
      if (!links.length) continue;
      // join an existing correlation if any related signal already belongs to a live one; otherwise open a new one
      const existingId = links.map((l) => l.x.correlationId).find(Boolean);
      const existing = existingId ? await this.db.correlations.get(orgId, existingId) : undefined;
      const group = existing && existing.status !== 'dismissed' ? existing : undefined;
      const members = group ? [...new Set([...group.signalIds, cur.id])] : [...new Set([cur.id, ...links.map((l) => l.x.id)])];
      const reasons = [...(group?.reasons ?? []), ...links.flatMap((l) => l.why)];
      const c = await this.build(orgId, group?.id, members, reasons);
      out.push(c);
      for (const id of c.signalIds) { const m = all.get(id); if (m) m.correlationId = c.id; }
    }
    return out;
  }

  private async build(orgId: string, existingId: string | undefined, signalIds: string[], reasons: CorrelationReason[]): Promise<Correlation> {
    const sigs = (await Promise.all(signalIds.map((id) => this.db.signals.get(orgId, id)))).filter(Boolean) as Signal[];
    const asset = sigs.find((s) => s.assetId)?.assetId, identity = sigs.find((s) => s.identityId)?.identityId;
    const cves = [...new Set(sigs.flatMap((s) => s.cves))];
    const vulns = asset ? (await this.db.vulns.where(orgId, { assetId: asset })).filter((v) => v.status !== 'resolved' && (!cves.length || (v.cve && cves.includes(v.cve)) || v.priority?.level === 'immediate')) : [];
    if (vulns.length && cves.some((c) => vulns.some((v) => v.cve === c))) reasons.push({ type: 'vulnerability', value: cves.find((c) => vulns.some((v) => v.cve === c))!, confidence: WEIGHT.vulnerability, source: 'inventory' });
    const times = sigs.map((s) => Date.parse(s.at)), span = Math.max(...times) - Math.min(...times);
    reasons.push({ type: 'time', value: `${Math.round(span / 1000)}s window`, confidence: Math.max(0.3, 1 - span / WINDOW_MS()), source: 'timestamps' });
    const dedup = new Map<string, CorrelationReason>(); for (const r of reasons) { const k = `${r.type}:${r.value}`; if (!dedup.has(k) || dedup.get(k)!.confidence < r.confidence) dedup.set(k, r); }
    const uniq = [...dedup.values()], confidence = CorrelationService.combine(uniq);
    const assetRec = asset ? await this.db.inventory.get(orgId, asset) : undefined, idRec = identity ? await this.db.identities.get(orgId, identity) : undefined;
    const sources = new Set(sigs.map((s) => s.source)), top = sigs.reduce<Severity>((m, s) => (SEV_POINTS[s.severity] > SEV_POINTS[m] ? s.severity : m), 'info');
    const risk = Math.min(100, Math.round((SEV_POINTS[top] + Math.min(15, (sources.size - 1) * 5) + ({ critical: 10, high: 6, medium: 3, low: 0 } as const)[assetRec?.criticality ?? 'low'] + (assetRec?.internetFacing ? 5 : 0) + (vulns.some((v) => v.kev || v.priority?.level === 'immediate') ? 10 : vulns.length ? 4 : 0) + (idRec?.privileged ? 8 : 0)) * (0.6 + 0.4 * confidence)));
    const rec: string[] = [];
    if (assetRec) rec.push(`Review activity on ${assetRec.name}; consider an endpoint isolation proposal (requires approval).`);
    if (vulns.length) rec.push(`Prioritise remediation of ${vulns.map((v) => v.cve ?? v.title).slice(0, 3).join(', ')} on ${assetRec?.name ?? 'the affected asset'}.`);
    if (idRec) rec.push(`Review the sessions and recent activity of ${idRec.name}${idRec.privileged ? ' (privileged account)' : ''}.`);
    rec.push('This correlation is a hypothesis built from the listed reasons; confirm or dismiss it after investigation.');
    const base = { signalIds, assetId: asset, identityId: identity, vulnerabilityIds: vulns.map((v) => v.id), reasons: uniq, confidence, riskScore: risk, recommendation: rec, updatedAt: now() };
    let c: Correlation;
    if (existingId) c = await this.db.correlations.update(orgId, existingId, (r) => { Object.assign(r, base); });
    else { c = { id: newId('cor'), orgId, status: 'probable', createdAt: now(), ...base }; await this.db.correlations.put(c); await this.audit.append(orgId, 'system', 'correlation.created', { correlationId: c.id, signals: signalIds.length, confidence, risk }); }
    for (const sid of signalIds) await this.db.signals.update(orgId, sid, { correlationId: c.id });
    return this.maybeOpenCase(c, sigs, top);
  }

  /** Opens (once) a case for a significant correlation, or enriches the one that exists. Idempotent per correlation. */
  private async maybeOpenCase(c: Correlation, sigs: Signal[], top: Severity): Promise<Correlation> {
    if (c.status === 'dismissed') return c;
    if (c.caseId) {
      const cs = await this.db.cases.get(c.orgId, c.caseId);
      if (cs) { await this.cases.link({ orgId: c.orgId, userId: 'system' }, cs.id, { signalIds: c.signalIds, assetIds: c.assetId ? [c.assetId] : [], identityIds: c.identityId ? [c.identityId] : [], vulnerabilityIds: c.vulnerabilityIds }); await this.db.cases.update(c.orgId, cs.id, (r) => { r.risk = c.riskScore; r.severity = CasesService.severityMax(r.severity, top); r.recommendations = c.recommendation; }); }
      return c;
    }
    if (c.riskScore < AUTO_CASE_RISK()) return c;
    const asset = c.assetId ? await this.db.inventory.get(c.orgId, c.assetId) : undefined;
    const opened = await this.cases.open({ orgId: c.orgId, userId: 'system' }, { name: `Correlated activity on ${asset?.name ?? sigs[0]?.host ?? 'multiple sources'} (${[...new Set(sigs.map((s) => s.source))].join(' + ')})`, description: `Auto-opened from correlation ${c.id}: ${c.reasons.filter((r) => r.type !== 'time').map((r) => `${r.type}=${r.value} (${r.confidence})`).join(', ')}. Confidence ${c.confidence}: probable, not confirmed.`,
      severity: top, assetIds: c.assetId ? [c.assetId] : [], identityIds: c.identityId ? [c.identityId] : [], vulnerabilityIds: c.vulnerabilityIds, signalIds: c.signalIds, recommendations: c.recommendation }, 'correlation', { correlationId: c.id, risk: c.riskScore });
    return this.db.correlations.update(c.orgId, c.id, { caseId: opened.id });
  }

  async list(orgId: string, status?: string) { return (await this.db.correlations.list(orgId, (c) => !status || c.status === status)).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)); }
  async detail(orgId: string, id: string) {
    const c = await this.db.correlations.get(orgId, id); if (!c) throw new NotFoundException('correlation not found');
    return { correlation: c, signals: (await Promise.all(c.signalIds.map((s) => this.db.signals.get(orgId, s)))).filter(Boolean) };
  }
  /** Only a human can promote a probabilistic link to "confirmed" (or dismiss it). */
  async decide(me: Principal, id: string, status: 'confirmed' | 'dismissed', note: string) {
    if (!(await this.db.correlations.get(me.orgId, id))) throw new NotFoundException('correlation not found');
    const out = await this.db.correlations.update(me.orgId, id, { status, updatedAt: now() });
    await this.audit.append(me.orgId, me.userId, `correlation.${status}`, { correlationId: id, note });
    if (out.caseId) await this.cases.addTimeline(me.orgId, out.caseId, me.userId, 'note', `correlation ${status} by analyst: ${note}`);
    return out;
  }
}
