/**
 * Reproducible in-process performance probe (memory repositories, simulated ports, one Node process on the local machine).
 *   npm run perf -w apps/api            # PERF_VULNS=500 PERF_SIGNALS=2000 PERF_CONCURRENCY=50 by default
 * It measures THIS code on THIS machine; it is not a capacity claim for any deployment (PostgreSQL, Redis and the network change everything).
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';

for (const k of ['REDIS_URL', 'DATABASE_URL', 'OBJECT_STORE_BUCKET', 'INFRA_MODE', 'ANALYTICS_URL', 'OIDC_ISSUER']) delete process.env[k];
process.env.RATE_LIMIT_PER_MIN = '0';
const N_VULNS = Number(process.env.PERF_VULNS ?? 500), N_SIGNALS = Number(process.env.PERF_SIGNALS ?? 2000), CONC = Number(process.env.PERF_CONCURRENCY ?? 50);
const pct = (xs: number[], p: number) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]; };
const rows: Array<Record<string, string | number>> = [];

(async () => {
  const app = await NestFactory.create(AppModule, { logger: false }); await app.listen(0);
  const base = `http://127.0.0.1:${new URL((await app.getUrl()).replace('[::1]', '127.0.0.1')).port}/api/v1`;
  const call = async (method: string, path: string, body?: unknown) => { const t0 = performance.now(); const r = await fetch(base + path, { method, headers: { 'x-api-key': 'dev-analyst', 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); const buf = await r.arrayBuffer(); if (!r.ok) throw new Error(`${method} ${path} ${r.status}`); return { ms: performance.now() - t0, json: () => JSON.parse(Buffer.from(buf).toString()), bytes: buf.byteLength }; };
  const measure = async (name: string, n: number, fn: (i: number) => Promise<{ ms: number }>, conc = 1) => {
    const lat: number[] = [], t0 = performance.now(); let next = 0;
    await Promise.all(Array.from({ length: conc }, async () => { while (next < n) { const i = next++; lat.push((await fn(i)).ms); } }));
    const wall = performance.now() - t0; rows.push({ scenario: name, requests: n, concurrency: conc, 'total s': +(wall / 1000).toFixed(2), 'req/s': Math.round(n / (wall / 1000)), 'p50 ms': +pct(lat, 50).toFixed(1), 'p95 ms': +pct(lat, 95).toFixed(1), 'max ms': +Math.max(...lat).toFixed(1) });
  };

  const assets: string[] = [];
  await measure(`create ${50} assets`, 50, async (i) => { const r = await call('POST', '/inventory/assets', { type: 'server', identifier: `srv-${i}`, criticality: i % 7 === 0 ? 'critical' : 'medium', internetFacing: i % 3 === 0 }); assets.push(r.json().id); return r; });
  await measure(`create ${N_VULNS} vulnerabilities (each re-prioritised with graph context)`, N_VULNS, (i) => call('POST', '/vulns', { assetId: assets[i % assets.length], cve: `CVE-2024-${String(1000 + i)}`, title: `vuln ${i}`, severity: (['low', 'medium', 'high', 'critical'] as const)[i % 4], source: 'perf', confidence: 'suspected' }));
  const batches = Math.ceil(N_SIGNALS / 500);
  await measure(`ingest ${N_SIGNALS} signals in batches of 500 (dedupe + correlation + playbook evaluation)`, batches, (b) => call('POST', '/signals', { signals: Array.from({ length: Math.min(500, N_SIGNALS - b * 500) }, (_, k) => ({ source: 'wazuh', sourceId: `p-${b}-${k}`, title: `alert ${k}`, severity: 'low', host: `srv-${(b * 500 + k) % 50}`, at: new Date(Date.now() - (b * 500 + k) * 60000).toISOString() })) }));
  await measure('GET /vulns?limit=50 (sorted by priority)', 60, () => call('GET', '/vulns?limit=50'));
  await measure('GET /ctem/priorities', 30, () => call('GET', '/ctem/priorities'));
  await measure('GET /dashboard/executive', 30, () => call('GET', '/dashboard/executive'));
  await measure(`GET /dashboard/executive, ${CONC} concurrent clients`, CONC * 2, () => call('GET', '/dashboard/executive'), CONC);
  await measure('GET /ctem/attack-paths', 20, () => call('GET', '/ctem/attack-paths'));
  await measure('POST /reports (technical PDF)', 5, () => call('POST', '/reports', { kind: 'technical' }));
  await measure('POST /reports (executive PDF)', 5, () => call('POST', '/reports', { kind: 'executive' }));
  const mem = process.memoryUsage();
  console.log(`\nSentinelMesh perf probe — node ${process.version}, ${process.platform}/${process.arch}, ${new Date().toISOString()}\nvulnerabilities=${N_VULNS} signals=${N_SIGNALS} (memory repositories, no network latency)\n`);
  console.table(rows);
  console.log(`heap used ${(mem.heapUsed / 1048576).toFixed(0)} MiB, rss ${(mem.rss / 1048576).toFixed(0)} MiB`);
  await app.close(); process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
