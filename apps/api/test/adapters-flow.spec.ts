import http from 'node:http';
import { AddressInfo } from 'node:net';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { WAFV2Client, ListRuleGroupsCommand } from '@aws-sdk/client-wafv2';
import { IAMClient } from '@aws-sdk/client-iam';
import { EC2Client } from '@aws-sdk/client-ec2';
import { AppModule } from '../src/app.module';
import { JOB_QUEUE, MemoryQueue } from '../src/queue/queue';
import { EXECUTION_LOCK, MemoryLock } from '../src/workflow/lock';
import { OBJECT_STORAGE } from '../src/storage/object-storage';
import { PORTS } from '../src/workflow/ports';
import { ApprovalSigner } from '../src/approvals/signer';
import { AwsInfraAdapter, AwsSecretProvider } from '../src/adapters/aws';
import { HttpHealthChecker } from '../src/adapters/health';
import { HttpForensicCollector } from '../src/adapters/forensics';
import { Db } from '../src/store/db';
import './helpers';

const endpoint = process.env.AWS_TEST_ENDPOINT;
const cfg = { endpoint, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' } };

/** Downstream service: only accepts the credential version that is currently "deployed". */
function downstream() {
  const accepted = new Set<string>(); const seen: string[] = [];
  const srv = http.createServer((req, res) => { const tok = /^Bearer (.+)$/.exec(String(req.headers.authorization))?.[1] ?? ''; seen.push(tok); res.statusCode = accepted.has(tok) ? 200 : 401; res.end('x'); });
  return new Promise<{ srv: http.Server; url: string; accepted: Set<string>; seen: string[] }>((r) => srv.listen(0, '127.0.0.1', () => r({ srv, url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}/healthz`, accepted, seen })));
}

(endpoint ? describe : describe.skip)('full flows on real adapters (AWS emulator + local HTTP services)', () => {
  beforeEach(async () => { await fetch(`${endpoint}/moto-api/reset`, { method: 'POST' }); });

  it('rotation: new secret is probed against the real service before the old one is revoked in Secrets Manager', async () => {
    const svc = await downstream();
    const mod = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(JOB_QUEUE).useValue(new MemoryQueue(3, 0)).overrideProvider(EXECUTION_LOCK).useValue(new MemoryLock()).overrideProvider(OBJECT_STORAGE).useValue({ put: async () => {}, get: async () => undefined })
      .overrideProvider(PORTS.SECRETS).useFactory({ inject: [ApprovalSigner], factory: (s: ApprovalSigner) => new AwsSecretProvider(new SecretsManagerClient(cfg), (p) => s.assertProof(p)) })
      .overrideProvider(PORTS.HEALTH).useFactory({ inject: [PORTS.SECRETS], factory: (sp: AwsSecretProvider) => new HttpHealthChecker({ urls: { payments: svc.url }, getSecret: (c, v) => sp.getValue(c, v), policy: { allowHttp: true, allowPrivateHosts: ['127.0.0.1'] } }) })
      .compile();
    process.env.HEALTH_RETRY_MS = '0';
    const app = mod.createNestApplication(); await app.init();
    const http_ = request(app.getHttpServer()); const sp = mod.get<AwsSecretProvider>(PORTS.SECRETS); const db = mod.get(Db); const queue = mod.get<MemoryQueue>(JOB_QUEUE);

    await http_.post('/api/v1/scans/ingest').set('x-api-key', 'dev-analyst').send({ format: 'secrets', source: 'gl', report: { findings: [{ rule: 'aws', secret: 'AKIAIOSFODNN7EXAMPLE', file: 'a.js', repo: 'payments', verified: true }] } }).expect(201);
    const cred = db.credentials.list('org_acme')[0];
    await sp.adopt(cred.id, 'old-secret'); svc.accepted.add('old-secret');
    // The deployed service trusts any 43-char generated secret (the new one) as well as the old one.
    svc.srv.removeAllListeners('request');
    svc.srv.on('request', (req, res) => { const tok = String(req.headers.authorization).replace('Bearer ', ''); svc.seen.push(tok); res.statusCode = tok.length > 20 || tok === 'old-secret' ? 200 : 401; res.end(); });

    const rot = await http_.post('/api/v1/secrets/rotate').set('x-api-key', 'dev-analyst').send({ credentialId: cred.id }).expect(202);
    await queue.idle();
    const ex = db.executions.get('org_acme', rot.body.executionId)!;
    expect(ex.steps.map((s) => s.status)).toEqual(['succeeded', 'succeeded', 'succeeded', 'awaiting_approval']);
    expect(await sp.getActive(cred.id)).toBe(2);
    expect(await sp.isValid(cred.id, 1)).toBe(true);                    // old key still valid while SecOps decides
    expect(svc.seen.length).toBe(1); expect(svc.seen[0]).not.toBe('old-secret'); // probe used the NEW secret
    expect(JSON.stringify(db.executions.list('org_acme'))).not.toContain(svc.seen[0]); // and it never leaked into persisted state

    const [a] = db.approvals.list('org_acme');
    await http_.post(`/api/v1/approvals/${a.id}/decision`).set('x-api-key', 'dev-approver').send({ decision: 'approved' }).expect(200);
    await queue.idle();
    expect(db.executions.get('org_acme', rot.body.executionId)!.status).toBe('succeeded');
    expect(await sp.isValid(cred.id, 1)).toBe(false);
    expect(await sp.isValid(cred.id, 2)).toBe(true);
    await app.close(); svc.srv.closeAllConnections(); svc.srv.close();
  });

  it('a failing probe rolls Secrets Manager back to the old version', async () => {
    const svc = await downstream(); // accepts nothing new
    svc.srv.removeAllListeners('request'); svc.srv.on('request', (req, res) => { res.statusCode = req.headers.authorization === 'Bearer old-secret' ? 200 : 503; res.end(); });
    const mod = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(JOB_QUEUE).useValue(new MemoryQueue(3, 0)).overrideProvider(EXECUTION_LOCK).useValue(new MemoryLock())
      .overrideProvider(PORTS.SECRETS).useFactory({ inject: [ApprovalSigner], factory: (s: ApprovalSigner) => new AwsSecretProvider(new SecretsManagerClient(cfg), (p) => s.assertProof(p)) })
      .overrideProvider(PORTS.HEALTH).useFactory({ inject: [PORTS.SECRETS], factory: (sp: AwsSecretProvider) => new HttpHealthChecker({ urls: { payments: svc.url }, getSecret: (c, v) => sp.getValue(c, v), policy: { allowHttp: true, allowPrivateHosts: ['127.0.0.1'] } }) })
      .compile();
    const app = mod.createNestApplication(); await app.init();
    const http_ = request(app.getHttpServer()); const sp = mod.get<AwsSecretProvider>(PORTS.SECRETS); const db = mod.get(Db); const queue = mod.get<MemoryQueue>(JOB_QUEUE);
    await http_.post('/api/v1/scans/ingest').set('x-api-key', 'dev-analyst').send({ format: 'secrets', source: 'gl', report: { findings: [{ rule: 'aws', secret: 'AKIAIOSFODNN7EXAMPLE', repo: 'payments', verified: true }] } });
    const cred = db.credentials.list('org_acme')[0]; await sp.adopt(cred.id, 'old-secret');
    const rot = await http_.post('/api/v1/secrets/rotate').set('x-api-key', 'dev-analyst').send({ credentialId: cred.id });
    await queue.idle();
    const ex = db.executions.get('org_acme', rot.body.executionId)!;
    expect(ex.status).toBe('failed'); expect(ex.steps[2].error).toMatch(/rolled back/);
    expect(await sp.getActive(cred.id)).toBe(1); expect(await sp.isValid(cred.id, 1)).toBe(true); expect(await sp.isValid(cred.id, 2)).toBe(false);
    expect(await sp.getValue(cred.id, 1)).toBe('old-secret');
    await app.close(); svc.srv.closeAllConnections(); svc.srv.close();
  });

  it('WAF mitigation: nothing exists in WAFv2 until approval, then the approved rule group is created', async () => {
    const waf = new WAFV2Client(cfg);
    const mod = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(JOB_QUEUE).useValue(new MemoryQueue(3, 0)).overrideProvider(EXECUTION_LOCK).useValue(new MemoryLock())
      .overrideProvider(PORTS.INFRA).useFactory({ inject: [ApprovalSigner], factory: (s: ApprovalSigner) => new AwsInfraAdapter({ waf, iam: new IAMClient(cfg), ec2: new EC2Client(cfg), isolation: {}, proofCheck: (p) => s.assertProof(p) }) })
      .compile();
    const app = mod.createNestApplication(); await app.init();
    const h = request(app.getHttpServer()); const queue = mod.get<MemoryQueue>(JOB_QUEUE); const db = mod.get(Db);
    const sim = await h.post('/api/v1/remediations/simulate').set('x-api-key', 'dev-analyst').send({ kind: 'waf', targetRef: 'api-gateway', submitForApproval: true, params: { rule: { name: 'block-sqli', action: 'block', addresses: ['203.0.113.0/24'] } } }).expect(201);
    expect(sim.body.plan.terraform).toContain('203.0.113.0/24');
    await queue.idle();
    expect((await waf.send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups ?? []).toHaveLength(0);
    const [a] = db.approvals.list('org_acme');
    await h.post(`/api/v1/approvals/${a.id}/decision`).set('x-api-key', 'dev-approver').send({ decision: 'approved' }).expect(200);
    await queue.idle();
    expect((await waf.send(new ListRuleGroupsCommand({ Scope: 'REGIONAL' }))).RuleGroups!.map((g) => g.Name)).toEqual(['block-sqli']);
    await app.close();
  });
});

describe('forensic collector (Prometheus/Loki/Kubernetes HTTP APIs, response-shape fakes)', () => {
  const fake = (routes: Record<string, (u: URL) => unknown>) => ((async (u: URL) => { const h = routes[u.pathname]; return h ? { ok: true, status: 200, json: async () => h(u) } : { ok: false, status: 404, json: async () => ({}) }; }) as unknown) as typeof fetch;
  const policy = { allowHttp: true, resolve: async () => ['93.184.216.34'] };

  it('merges the three sources and records gaps instead of failing', async () => {
    const seenQueries: string[] = [];
    const c = new HttpForensicCollector({ policy, prometheusUrl: 'http://prom', lokiUrl: 'http://loki', kubeApiUrl: 'http://kube', kubeToken: 't', fetchImpl: fake({
      '/api/v1/query': (u) => { seenQueries.push(u.searchParams.get('query')!); return { data: { result: [{ value: [0, '912'] }] } }; },
      '/loki/api/v1/query_range': () => ({ data: { result: [{ values: [['1', '401 /login'], ['2', '401 /login']] }] } }),
    }) });
    const b = await c.collect('auth-api', { gatewayLogs: ['gw line'] });
    expect(b.metrics['requestRate']).toBe('912');
    expect(b.logs).toEqual(['gw line', '401 /login', '401 /login']);
    expect((b.metrics['collectionGaps'] as string[])[0]).toMatch(/kubernetes: HTTP 404/);   // missing route → recorded, not fatal
    expect(seenQueries[0]).toContain('service="auth-api"');
  });
  it('rejects query-injection in the target name and private/unsafe source URLs', async () => {
    const c = new HttpForensicCollector({ policy, prometheusUrl: 'http://prom', fetchImpl: fake({}) });
    await expect(c.collect('x"} or vector(1) #', {})).rejects.toThrow(/invalid target/);
    const metadata = new HttpForensicCollector({ lokiUrl: 'https://169.254.169.254', fetchImpl: fake({}) });
    expect(((await metadata.collect('svc', {})).metrics['collectionGaps'] as string[])[0]).toMatch(/private/);
  });
});
