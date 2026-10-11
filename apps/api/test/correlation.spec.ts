import { currentCorrelation, fromHeaders, propagationHeaders, runWithCorrelation, correlationFor } from '../src/common/correlation';
import { AnalyticsClient } from '../src/analytics/analytics.client';
import { boot, ORG } from './helpers';

const TP = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';

describe('correlation headers (mesh cooperation)', () => {
  it('keeps valid request id / tenant / trace context and mints an id when missing or malformed', () => {
    const ok = fromHeaders({ 'x-request-id': 'req-1234abcd', 'x-tenant': 'org_acme', traceparent: TP, baggage: 'k=v' });
    expect(ok.headers).toEqual({ 'x-request-id': 'req-1234abcd', 'x-tenant': 'org_acme', traceparent: TP, baggage: 'k=v' });
    expect(fromHeaders({}).requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(fromHeaders({ 'x-request-id': 'short' }).requestId).not.toBe('short');          // too short to be a real id
    for (const bad of ['has space in it', 'inj"ected\r\nx-evil: 1', 'a'.repeat(200), '<script>alert(1)</script>']) {
      const c = fromHeaders({ 'x-request-id': bad, 'x-tenant': bad, traceparent: bad });
      expect(c.requestId).not.toBe(bad); expect(c.tenant).toBeUndefined(); expect(c.headers['traceparent']).toBeUndefined();
    }
  });

  it('only the allowlist is propagated: credentials never travel to other services', () => {
    const c = fromHeaders({ authorization: 'Bearer secret', 'x-api-key': 'k', cookie: 'sid=1', 'x-forwarded-for': '1.2.3.4', 'x-request-id': 'req-1234abcd' });
    expect(Object.keys(c.headers)).toEqual(['x-request-id']);
  });

  it('propagation is scoped to the request (no bleed between concurrent requests)', async () => {
    const seen: string[] = [];
    await Promise.all(['req-aaaaaaaa', 'req-bbbbbbbb', 'req-cccccccc'].map((id, i) => runWithCorrelation(correlationFor(id, `t${i}`), async () => {
      await new Promise((r) => setTimeout(r, 15 - i * 5));          // finish out of order
      seen.push(`${id}:${propagationHeaders()['x-tenant']}:${currentCorrelation()!.requestId}`);
    })));
    expect(seen.sort()).toEqual(['req-aaaaaaaa:t0:req-aaaaaaaa', 'req-bbbbbbbb:t1:req-bbbbbbbb', 'req-cccccccc:t2:req-cccccccc']);
    expect(propagationHeaders()).toEqual({});
  });

  it('calls to the analytics service carry the correlation headers and nothing else of the caller', async () => {
    let sent: Record<string, string> = {};
    const fetchImpl = (async (_u: URL, init: { headers: Record<string, string> }) => { sent = init.headers; return { ok: true, json: async () => ({ severity: 'low', exposureScore: 1, suppressed: false, rationale: [] }) }; }) as unknown as typeof fetch;
    const client = new AnalyticsClient('http://analytics:8000', fetchImpl);
    await runWithCorrelation(fromHeaders({ 'x-request-id': 'req-1234abcd', 'x-tenant': 'org_acme', traceparent: TP, authorization: 'Bearer secret' }), () =>
      client.correlate({ ruleId: 'r', kind: 'vulnerability', severity: 'low' }));
    expect(sent).toMatchObject({ 'x-request-id': 'req-1234abcd', 'x-tenant': 'org_acme', traceparent: TP, 'content-type': 'application/json' });
    expect(sent['authorization']).toBeUndefined();
  });
});

describe('correlation over HTTP', () => {
  it('echoes or mints x-request-id, writes it into the audit trail, and keeps it across the async worker', async () => {
    const t = await boot();
    const r1 = await t.viewer.get('/api/v1/me').set('x-request-id', 'req-from-gw-0001').expect(200);
    expect(r1.headers['x-request-id']).toBe('req-from-gw-0001');
    expect((await t.viewer.get('/api/v1/me').expect(200)).headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
    expect((await t.viewer.get('/api/v1/me').set('x-request-id', 'bad id!').expect(200)).headers['x-request-id']).not.toBe('bad id!');

    await t.analyst.post('/api/v1/scans/ingest', { format: 'secrets', source: 'gl', report: { findings: [{ rule: 'aws', secret: 'AKIAIOSFODNN7EXAMPLE', repo: 'p', verified: true }] } }).set('x-request-id', 'req-ingest-0001').expect(201);
    const cred = (await t.db.credentials.list(ORG))[0]; t.secrets.seed(cred.id);
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).set('x-request-id', 'req-rotate-0001').expect(202);
    await t.queue.idle();
    const audit = await t.audit.list(ORG);
    expect(audit.find((e) => e.event === 'scan.ingested')!.data).toMatchObject({ requestId: 'req-ingest-0001' });
    const worker = audit.filter((e) => e.event === 'step.succeeded' && (e.data as any).executionId === rot.body.executionId);
    expect(worker.length).toBeGreaterThan(0);
    for (const e of worker) expect(e.data).toMatchObject({ requestId: 'req-rotate-0001' });   // worker continues the originating trace
    expect((await t.audit.verify(ORG)).ok).toBe(true);
    await t.app.close();
  });

  it('x-tenant must agree with the authenticated organisation (and can be made mandatory)', async () => {
    const t = await boot();
    await t.viewer.get('/api/v1/me').set('x-tenant', ORG).expect(200);
    await t.viewer.get('/api/v1/me').set('x-tenant', 'org_other').expect(403);
    process.env.MESH_ENFORCE_TENANT = '1';
    try {
      await t.viewer.get('/api/v1/me').expect(403);
      await t.viewer.get('/api/v1/me').set('x-tenant', ORG).expect(200);
    } finally { delete process.env.MESH_ENFORCE_TENANT; }
    await t.app.close();
  });
});
