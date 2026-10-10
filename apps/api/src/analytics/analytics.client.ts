import { Injectable, Logger } from '@nestjs/common';
import { AssetContext, PolicyDoc, Severity } from '../store/models';

export interface CorrelateInput { ruleId: string; kind: 'vulnerability' | 'secret'; severity: Severity; likelyFalsePositive?: boolean; asset?: Pick<AssetContext, 'internetFacing' | 'behindGateway' | 'handlesCriticalData' | 'environment'> }
export interface CorrelateOutput { severity: Severity; exposureScore: number; suppressed: boolean; suppressionReason?: string; rationale: string[] }

export interface LeastPrivilegeOutput { granted: string[]; used: string[]; unused: string[]; usageRatio: number; proposedPolicy: PolicyDoc }

export interface EvidenceItem { id: string; type: string; text: string }
export interface SummaryOutput { summary: string; citations: string[]; ungroundedClaims: number }

const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const BASE_SCORE: Record<Severity, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 5 };

/** Local mirror of services/analytics (used when the Python service is unreachable → fail-safe, never fail-open). */
export function localCorrelate(i: CorrelateInput): CorrelateOutput {
  const rationale: string[] = [];
  let score = BASE_SCORE[i.severity];
  if (i.likelyFalsePositive) {
    return { severity: 'info', exposureScore: 0, suppressed: true, suppressionReason: 'likely false positive (test/fixture/placeholder)', rationale: ['matched false-positive heuristics'] };
  }
  const a = i.asset;
  if (!a) rationale.push('no asset context: severity kept as reported (conservative)');
  else {
    if (a.internetFacing) { score += 15; rationale.push('asset is internet-facing (+15)'); } else { score -= 15; rationale.push('asset not internet-facing (-15)'); }
    if (a.behindGateway) { score -= 10; rationale.push('protected by API gateway (-10)'); }
    if (a.handlesCriticalData) { score += 10; rationale.push('asset handles critical data (+10)'); }
    if (a.environment === 'dev') { score -= 20; rationale.push('dev environment (-20)'); }
  }
  score = Math.max(0, Math.min(100, score));
  const severity: Severity = score >= 85 ? 'critical' : score >= 65 ? 'high' : score >= 40 ? 'medium' : score >= 15 ? 'low' : 'info';
  // Secrets never get downgraded below the reported level: a leaked key is live regardless of the asset.
  const final = i.kind === 'secret' && ORDER.indexOf(severity) < ORDER.indexOf(i.severity) ? i.severity : severity;
  return { severity: final, exposureScore: score, suppressed: false, rationale };
}

export function localLeastPrivilege(granted: string[], usedEvents: string[], resources: string[]): LeastPrivilegeOutput {
  const used = [...new Set(usedEvents)].filter((a) => granted.includes(a) || granted.some((g) => g.endsWith('*') && a.startsWith(g.slice(0, -1)))).sort();
  const unused = granted.filter((g) => !used.includes(g)).sort();
  return {
    granted, used, unused, usageRatio: granted.length ? used.length / granted.length : 0,
    proposedPolicy: { version: '2012-10-17', statements: used.length ? [{ effect: 'Allow', actions: used, resources }] : [] },
  };
}

/** Grounded summary: every sentence is derived from an evidence item and cites its id. */
export function localSummary(evidence: EvidenceItem[]): SummaryOutput {
  if (!evidence.length) return { summary: 'No evidence was captured; no conclusions can be drawn.', citations: [], ungroundedClaims: 0 };
  const lines = evidence.map((e) => `- [${e.id}] ${e.type}: ${e.text}`);
  return { summary: lines.join('\n'), citations: evidence.map((e) => e.id), ungroundedClaims: 0 };
}

@Injectable()
export class AnalyticsClient {
  private log = new Logger('Analytics');
  constructor(private baseUrl = process.env.ANALYTICS_URL, private fetchImpl: typeof fetch = fetch, private timeoutMs = 2000) {}

  private async post<T>(path: string, body: unknown): Promise<T | undefined> {
    if (!this.baseUrl) return undefined;
    try {
      // baseUrl is operator config (env), never request data, so it cannot be steered by a caller (no SSRF surface).
      const url = new URL(path, this.baseUrl);
      const res = await this.fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(this.timeoutMs) });
      if (!res.ok) throw new Error(`status ${res.status}`);
      return (await res.json()) as T;
    } catch (e) {
      this.log.warn(`analytics ${path} unavailable, using local fallback: ${(e as Error).message}`);
      return undefined;
    }
  }

  async correlate(i: CorrelateInput): Promise<CorrelateOutput> {
    return (await this.post<CorrelateOutput>('/v1/correlate', i)) ?? localCorrelate(i);
  }
  async leastPrivilege(granted: string[], usedEvents: string[], resources: string[]): Promise<LeastPrivilegeOutput> {
    return (await this.post<LeastPrivilegeOutput>('/v1/iam/least-privilege', { granted, used_events: usedEvents, resources })) ?? localLeastPrivilege(granted, usedEvents, resources);
  }
  async summarize(evidence: EvidenceItem[]): Promise<SummaryOutput> {
    return (await this.post<SummaryOutput>('/v1/forensics/summary', { evidence })) ?? localSummary(evidence);
  }
}
