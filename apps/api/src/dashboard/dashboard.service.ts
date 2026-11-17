import { Injectable } from '@nestjs/common';
import { Db } from '../store/db';
import { ConnectorsService } from '../connectors/connectors.service';
import { IamService } from '../iam/iam.service';
import { Entitlements } from '../platform/entitlements';

const day = (iso: string) => iso.slice(0, 10);
const clamp = (n: number, a: number, b: number) => Math.max(a, Math.min(b, n));

/** Everything here is computed from stored records. A dashboard with no data says so; nothing is estimated or back-filled. */
@Injectable()
export class DashboardService {
  constructor(private db: Db, private connectors: ConnectorsService, private iam: IamService, private ent: Entitlements) {}

  /**
   * Global risk (0-100) is a transparent sum, not a model: mean of the five highest open-vulnerability priorities (≤ 50 pts), + 5 per open
   * critical case (≤ 20), + 3 per confirmed open exposure (≤ 15), + 5 per privileged account without MFA (≤ 15).
   */
  private inflight = new Map<string, Promise<unknown>>();
  private cache = new Map<string, { at: number; v: unknown }>();
  /**
   * Identical concurrent requests share one computation (no staleness), and the result is reused for DASHBOARD_CACHE_SEC (default 5 s,
   * 0 under test) so a wall of console clients cannot make every one of them rescan the organisation.
   */
  async executive(orgId: string, days = 30): Promise<Awaited<ReturnType<DashboardService['compute']>>> {
    const key = `${orgId}:${days}`, ttl = (process.env.NODE_ENV === 'test' ? 0 : Number(process.env.DASHBOARD_CACHE_SEC ?? 5)) * 1000, hit = this.cache.get(key);
    if (ttl && hit && Date.now() - hit.at < ttl) return hit.v as never;
    const running = this.inflight.get(key); if (running) return running as never;
    const p = this.compute(orgId, days).then((v) => { if (ttl) this.cache.set(key, { at: Date.now(), v }); return v; }).finally(() => this.inflight.delete(key));
    this.inflight.set(key, p); return p;
  }

  private async compute(orgId: string, days: number) {
    const [assets, vulns, cases, exposures, signals, ident, risks, runs, correlations, ch] = await Promise.all([this.db.inventory.list(orgId), this.db.vulns.list(orgId), this.db.cases.list(orgId), this.db.exposures.list(orgId), this.db.signals.list(orgId), this.db.identities.list(orgId), this.iam.risks(orgId), this.db.runs.list(orgId, (r) => r.status === 'awaiting_approval'), this.db.correlations.list(orgId), this.connectors.health(orgId)]);
    const openV = vulns.filter((v) => v.status === 'open' || v.status === 'in_progress'), top = [...openV].sort((a, b) => (b.priority?.score ?? 0) - (a.priority?.score ?? 0));
    const activeCases = cases.filter((c) => c.status !== 'closed' && c.status !== 'resolved'), openExp = exposures.filter((e) => e.status === 'open');
    const noMfa = risks.filter((r) => r.code === 'privileged_no_mfa' && r.confidence === 'confirmed').length;
    const factors = [
      { name: 'Top open vulnerabilities (mean priority of up to 5)', points: top.length ? Math.round((top.slice(0, 5).reduce((s, v) => s + (v.priority?.score ?? 0), 0) / Math.min(5, top.length)) * 0.5) : 0, max: 50 },
      { name: 'Open critical cases', points: clamp(activeCases.filter((c) => c.severity === 'critical').length * 5, 0, 20), max: 20 },
      { name: 'Confirmed open exposures', points: clamp(openExp.filter((e) => e.confidence === 'confirmed').length * 3, 0, 15), max: 15 },
      { name: 'Privileged accounts without MFA', points: clamp(noMfa * 5, 0, 15), max: 15 },
    ];
    const score = factors.reduce((s, f) => s + f.points, 0), hasData = assets.length + vulns.length + cases.length + ident.length > 0;
    const since = new Date(Date.now() - days * 86400000), series = new Map<string, { date: string; vulnerabilities: number; cases: number; signals: number }>();
    for (let i = days - 1; i >= 0; i--) { const d = day(new Date(Date.now() - i * 86400000).toISOString()); series.set(d, { date: d, vulnerabilities: 0, cases: 0, signals: 0 }); }
    for (const v of vulns) { const p = series.get(day(v.detectedAt)); if (p) p.vulnerabilities++; }
    for (const c of cases) { const p = series.get(day(c.openedAt)); if (p) p.cases++; }
    for (const s of signals) { const p = series.get(day(s.at)); if (p) p.signals++; }
    const linkedIdentities = new Set(activeCases.flatMap((c) => c.identityIds)), channels = await this.db.channels.list(orgId);
    return {
      generatedAt: new Date().toISOString(), hasData, plan: await this.ent.describe(orgId),
      risk: { score: hasData ? score : null, level: !hasData ? 'no data' : score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low', factors, method: 'transparent additive score; see factors' },
      assets: { total: assets.length, internetFacing: assets.filter((a) => a.internetFacing).length, stale: assets.filter((a) => a.status === 'stale').length, unverifiedOwnership: assets.filter((a) => a.ownership.status !== 'verified').length },
      vulnerabilities: { open: openV.length, immediate: openV.filter((v) => v.priority?.level === 'immediate').length, critical: openV.filter((v) => v.severity === 'critical').length, kev: openV.filter((v) => v.kev).length, overdue: openV.filter((v) => v.dueDate && Date.parse(v.dueDate) < Date.now()).length },
      cases: { active: activeCases.length, bySeverity: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, activeCases.filter((c) => c.severity === s).length])), probableCorrelations: correlations.filter((c) => c.status === 'probable').length },
      identities: { total: ident.length, privileged: ident.filter((i) => i.privileged).length, inActiveCases: linkedIdentities.size, riskyConfirmed: new Set(risks.filter((r) => r.code !== 'privileged' && r.confidence === 'confirmed' && ['critical', 'high'].includes(r.severity)).map((r) => r.identityId)).size, note: 'there is no automatic verdict of "compromised": identities appear here only when linked to an open case' },
      exposures: { open: openExp.length, confirmed: openExp.filter((e) => e.confidence === 'confirmed').length, suspected: openExp.filter((e) => e.confidence !== 'confirmed').length },
      priorities: top.slice(0, 5).map((v) => ({ id: v.id, title: v.title, cve: v.cve, assetId: v.assetId, priority: v.priority?.level, score: v.priority?.score, explanation: v.priority?.explanation })),
      approvalsPending: runs.length,
      trend: { days, series: [...series.values()].filter((p) => new Date(p.date) >= since) },
      integrations: { connectors: ch, notificationChannels: channels.map((c) => ({ id: c.id, name: c.name, kind: c.kind, enabled: c.enabled })) },
      limitations: ['Counts reflect only data ingested into SentinelMesh (connectors that are not configured or not synchronised contribute nothing).', 'Risk is a heuristic summary of the factors shown, not a probability of compromise.'],
    };
  }
}
