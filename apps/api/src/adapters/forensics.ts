import { assertSafeUrl, UrlPolicy } from '../common/ssrf';
import { ForensicBundle, ForensicCollector } from '../workflow/ports';

export interface ForensicSources {
  prometheusUrl?: string;   // GET /api/v1/query?query=…
  lokiUrl?: string;         // GET /loki/api/v1/query_range
  kubeApiUrl?: string;      // GET /api/v1/namespaces/{ns}/pods?labelSelector=app={target}
  kubeToken?: string; namespace?: string;
  policy?: UrlPolicy; timeoutMs?: number; fetchImpl?: typeof fetch;
}

/**
 * Collects metrics (Prometheus), logs (Loki) and container state (Kubernetes) for the target service at alert time.
 * Each source is best-effort: a missing/failed source is recorded as a gap in the evidence instead of aborting the capture
 * (losing the other evidence would be worse). The target name is strictly validated before it is placed in any query.
 */
export class HttpForensicCollector implements ForensicCollector {
  constructor(private s: ForensicSources) {}
  private async get(base: string, path: string, params: Record<string, string>, headers: Record<string, string> = {}) {
    const url = await assertSafeUrl(base, this.s.policy);
    const u = new URL(path, url); for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    const r = await (this.s.fetchImpl ?? fetch)(u, { headers, redirect: 'manual', signal: AbortSignal.timeout(this.s.timeoutMs ?? 8000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json() as Promise<any>;
  }

  async collect(target: string, ctx: Record<string, unknown>): Promise<ForensicBundle> {
    if (!/^[a-zA-Z0-9][\w.-]{0,62}$/.test(target)) throw new Error('invalid target name');
    const gaps: string[] = []; const gap = (src: string, e: unknown) => gaps.push(`${src}: ${(e as Error).message}`);
    const metrics: Record<string, unknown> = { target, capturedAt: new Date().toISOString() };
    const logs: string[] = [...((ctx['gatewayLogs'] as string[] | undefined) ?? [])];
    let containerState: Record<string, unknown> = { target };

    if (this.s.prometheusUrl) {
      for (const [name, q] of Object.entries({ requestRate: `sum(rate(http_requests_total{service="${target}"}[1m]))`, cpu: `sum(rate(container_cpu_usage_seconds_total{pod=~"${target}.*"}[1m]))` })) {
        try { const j = await this.get(this.s.prometheusUrl, '/api/v1/query', { query: q }); metrics[name] = j.data?.result?.[0]?.value?.[1] ?? null; } catch (e) { gap('prometheus', e); }
      }
    }
    if (this.s.lokiUrl) {
      try {
        const end = Date.now(); const j = await this.get(this.s.lokiUrl, '/loki/api/v1/query_range', { query: `{app="${target}"}`, limit: '500', start: String((end - 15 * 60_000) * 1e6), end: String(end * 1e6) });
        for (const stream of j.data?.result ?? []) for (const [, line] of stream.values ?? []) logs.push(String(line));
      } catch (e) { gap('loki', e); }
    }
    if (this.s.kubeApiUrl) {
      try {
        const j = await this.get(this.s.kubeApiUrl, `/api/v1/namespaces/${encodeURIComponent(this.s.namespace ?? 'default')}/pods`, { labelSelector: `app=${target}` }, this.s.kubeToken ? { authorization: `Bearer ${this.s.kubeToken}` } : {});
        containerState = { target, pods: (j.items ?? []).map((p: any) => ({ name: p.metadata?.name, phase: p.status?.phase, node: p.spec?.nodeName, restarts: (p.status?.containerStatuses ?? []).reduce((n: number, c: any) => n + (c.restartCount ?? 0), 0), images: (p.spec?.containers ?? []).map((c: any) => c.image) })) };
      } catch (e) { gap('kubernetes', e); }
    }
    if (gaps.length) metrics['collectionGaps'] = gaps;
    return { metrics, logs, containerState };
  }
}
