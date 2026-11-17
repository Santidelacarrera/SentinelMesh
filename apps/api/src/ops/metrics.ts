import { Controller, ForbiddenException, Get, Header, Headers, Injectable, NestMiddleware, ServiceUnavailableException, UseGuards, Inject } from '@nestjs/common';
import { timingSafeEqual } from 'node:crypto';
import { JOB_QUEUE, JobQueue } from '../queue/queue';
import { PgBackend } from '../store/pg';
import { Me, Perm, Principal, RolesGuard } from '../auth/auth';
import { OpsService } from './ops.service';

const BUCKETS = [0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
const esc = (v: string) => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
const fmt = (l: Record<string, string>) => { const k = Object.keys(l).sort(); return k.length ? `{${k.map((x) => `${x}="${esc(l[x])}"`).join(',')}}` : ''; };

/** Minimal Prometheus-compatible registry (counters, one latency histogram, pull gauges). No labels carry tenant data or identifiers. */
@Injectable()
export class Metrics {
  private counters = new Map<string, Map<string, number>>();
  private help = new Map<string, string>();
  private hist = new Map<string, { buckets: number[]; sum: number; count: number }>();
  private gauges = new Map<string, { help: string; fn: () => Promise<number> | number }>();
  readonly startedAt = Date.now();
  inc(name: string, labels: Record<string, string> = {}, by = 1, help = '') {
    const m = this.counters.get(name) ?? this.counters.set(name, new Map()).get(name)!; if (help) this.help.set(name, help);
    const k = fmt(labels); m.set(k, (m.get(k) ?? 0) + by);
  }
  observe(name: string, seconds: number, labels: Record<string, string> = {}) {
    const k = `${name}${fmt(labels)}`, h = this.hist.get(k) ?? this.hist.set(k, { buckets: BUCKETS.map(() => 0), sum: 0, count: 0 }).get(k)!;
    BUCKETS.forEach((b, i) => { if (seconds <= b) h.buckets[i]++; }); h.sum += seconds; h.count++;
  }
  gauge(name: string, help: string, fn: () => Promise<number> | number) { this.gauges.set(name, { help, fn }); }
  async render(): Promise<string> {
    const out: string[] = [];
    for (const [n, m] of this.counters) { out.push(`# HELP ${n} ${this.help.get(n) ?? n}`, `# TYPE ${n} counter`); for (const [l, v] of m) out.push(`${n}${l} ${v}`); }
    const names = new Set([...this.hist.keys()].map((k) => k.split('{')[0]));
    for (const n of names) {
      out.push(`# HELP ${n} request latency in seconds`, `# TYPE ${n} histogram`);
      for (const [k, h] of this.hist) { if (!k.startsWith(n)) continue; const lab = k.slice(n.length).replace(/^\{|\}$/g, ''); h.buckets.forEach((c, i) => out.push(`${n}_bucket{${lab}${lab ? ',' : ''}le="${BUCKETS[i]}"} ${c}`)); out.push(`${n}_bucket{${lab}${lab ? ',' : ''}le="+Inf"} ${h.count}`, `${n}_sum${lab ? `{${lab}}` : ''} ${h.sum}`, `${n}_count${lab ? `{${lab}}` : ''} ${h.count}`); }
    }
    out.push('# TYPE sentinel_uptime_seconds gauge', `sentinel_uptime_seconds ${Math.round((Date.now() - this.startedAt) / 1000)}`, '# TYPE sentinel_process_resident_memory_bytes gauge', `sentinel_process_resident_memory_bytes ${process.memoryUsage().rss}`);
    for (const [n, g] of this.gauges) { try { out.push(`# HELP ${n} ${g.help}`, `# TYPE ${n} gauge`, `${n} ${await g.fn()}`); } catch { /* a failing collector must not break the scrape */ } }
    return `${out.join('\n')}\n`;
  }
}

@Injectable()
export class MetricsMiddleware implements NestMiddleware {
  constructor(private m: Metrics) {}
  use(req: any, res: any, next: () => void) {
    const t0 = process.hrtime.bigint();
    res.on('finish', () => {
      const route = String(req.route?.path ?? 'unmatched').replace(/:[A-Za-z]+/g, ':id'), s = Number(process.hrtime.bigint() - t0) / 1e9, cls = `${Math.floor(res.statusCode / 100)}xx`;
      this.m.inc('sentinel_http_requests_total', { method: req.method, status: cls }, 1, 'HTTP requests by method and status class');
      this.m.observe('sentinel_http_request_duration_seconds', s, { method: req.method, route });
    });
    next();
  }
}

@Controller()
export class OpsController {
  constructor(private m: Metrics, @Inject(JOB_QUEUE) private queue: JobQueue, private pg: PgBackend, private ops: OpsService) {
    m.gauge('sentinel_queue_waiting', 'jobs waiting in the workflow queue', async () => (await queue.depth()).waiting);
    m.gauge('sentinel_queue_failed', 'jobs that exhausted their retries', async () => (await queue.depth()).failed);
  }

  /** Prometheus scrape. Requires `Authorization: Bearer $METRICS_TOKEN`; without a configured token it is only served outside production. */
  @Get('metrics') @Header('Content-Type', 'text/plain; version=0.0.4')
  async metrics(@Headers('authorization') auth?: string) {
    const token = process.env.METRICS_TOKEN;
    if (token) { const got = /^Bearer (.+)$/i.exec(auth ?? '')?.[1] ?? '', a = Buffer.from(got), b = Buffer.from(token); if (a.length !== b.length || !timingSafeEqual(a, b)) throw new ForbiddenException('metrics token required'); }
    else if (process.env.NODE_ENV === 'production') throw new ForbiddenException('set METRICS_TOKEN to expose metrics in production');
    return this.m.render();
  }

  /** Liveness is /healthz. Readiness: can this replica actually serve (database reachable, queue reachable)? */
  @Get('readyz')
  async ready() {
    const checks: Record<string, string> = {};
    try { await this.pg.ping(); checks['database'] = this.pg.pool ? 'ok' : 'memory'; } catch (e) { checks['database'] = `FAILED: ${(e as Error).message.slice(0, 100)}`; }
    try { const d = await this.queue.depth(); checks['queue'] = `ok (waiting=${d.waiting}, failed=${d.failed})`; } catch (e) { checks['queue'] = `FAILED: ${(e as Error).message.slice(0, 100)}`; }
    if (Object.values(checks).some((c) => c.startsWith('FAILED'))) throw new ServiceUnavailableException({ ready: false, checks });
    return { ready: true, checks };
  }

  @Get('api/v1/ops/health') @UseGuards(RolesGuard) @Perm('settings:manage')
  health(@Me() me: Principal) { return this.ops.health(me.orgId); }
}
