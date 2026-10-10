import { boot, Env, ORG } from './helpers';

const sarif = (results: any[]) => ({ runs: [{ tool: { driver: { name: 'codeql', rules: [{ id: 'js/sql-injection', properties: { 'security-severity': '9.1' } }] } }, results }] });
const res = (ruleId: string, uri: string, text = 'SQL injection', level = 'error') => ({ ruleId, level, message: { text }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 10 } } }] });
const AWS = 'AKIAIOSFODNN7EXAMPLE';

let t: Env;
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });
const settle = () => t.queue.idle();

describe('auth & tenancy', () => {
  it('rejects missing keys and under-privileged roles', async () => {
    await t.http.get('/api/v1/exposures/summary').expect(401);
    await t.viewer.post('/api/v1/scans/ingest', {}).expect(403);
    await t.analyst.post('/api/v1/approvals/x/decision', { decision: 'approved' }).expect(403);
  });
  it('isolates organisations', async () => {
    const r = await t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'ci', report: sarif([res('js/sql-injection', 'api/x.js')]) }).expect(201);
    const f = (await t.db.findings.list(ORG))[0];
    await t.other.get(`/api/v1/findings/${f.id}/trace`).expect(404);
    const s = await t.other.get('/api/v1/exposures/summary').expect(200);
    expect(s.body.totals.open).toBe(0);
    expect(r.body.created).toBe(1);
  });
});

describe('ingest & false-positive suppression', () => {
  it('dedupes, correlates with asset context, and suppresses placeholders', async () => {
    await t.analyst.post('/api/v1/assets', { name: 'payments', internetFacing: true, behindGateway: false, handlesCriticalData: true, environment: 'prod' }).expect(201);
    await t.analyst.post('/api/v1/assets', { name: 'internal-tool', internetFacing: false, behindGateway: true, handlesCriticalData: false, environment: 'dev' }).expect(201);
    const report = sarif([res('js/sql-injection', 'payments/db.js'), res('js/sql-injection', 'internal-tool/db.js'), res('js/sql-injection', 'tests/fixtures/db.js')]);
    const a = await t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'ci', report }).expect(201);
    expect(a.body).toMatchObject({ created: 2, suppressed: 1, duplicates: 0 });
    const b = await t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'ci', report }).expect(201);
    expect(b.body).toMatchObject({ created: 0, duplicates: 3 });
    const s = (await t.viewer.get('/api/v1/exposures/summary').expect(200)).body;
    expect(s.top[0].asset).toBe('payments');
    expect(s.top[0].exposureScore).toBeGreaterThan(s.top[1].exposureScore);
    expect(s.totals.suppressed).toBe(1);
  });
  it('parses trivy, semgrep and zap and rejects malformed reports', async () => {
    await t.analyst.post('/api/v1/scans/ingest', { format: 'trivy', source: 't', report: { Results: [{ Target: 'img', Vulnerabilities: [{ VulnerabilityID: 'CVE-1', PkgName: 'openssl', Severity: 'HIGH' }] }] } }).expect(201);
    await t.analyst.post('/api/v1/scans/ingest', { format: 'semgrep', source: 's', report: { results: [{ check_id: 'r', path: 'a/b.py', start: { line: 1 }, extra: { severity: 'WARNING', message: 'm' } }] } }).expect(201);
    await t.analyst.post('/api/v1/scans/ingest', { format: 'zap', source: 'z', report: { site: [{ '@name': 'app', alerts: [{ pluginid: '1', name: 'XSS', riskcode: '3' }] }] } }).expect(201);
    await t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'x', report: { nope: 1 } }).expect(400);
    await t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'x', report: sarif([]), extra: 1 }).expect(400);
  });
  it('masks leaked secrets everywhere (storage, findings, audit) and filters fake ones', async () => {
    const r = await t.analyst.post('/api/v1/scans/ingest', { format: 'secrets', source: 'gitleaks', report: { findings: [
      { rule: 'aws-access-key', secret: AWS, file: 'src/config.js', line: 3, repo: 'payments', verified: true },
      { rule: 'generic-api-key', secret: 'YOUR_API_KEY_HERE', file: 'README.md', repo: 'payments' },
    ] } }).expect(201);
    expect(r.body).toMatchObject({ created: 1, suppressed: 1 });
    const dump = JSON.stringify([(await t.db.findings.list(ORG)), (await t.db.credentials.list(ORG)), (await t.audit.list(ORG)), (await t.storage.get(r.body.reportRef))!.toString()]);
    expect(dump).not.toContain(AWS);
    expect(dump).toContain('AKIA****LE');
  });
  it('traces a finding from report to simulated plan', async () => {
    await t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'ci', report: sarif([res('js/sql-injection', 'api/x.js')]) });
    const f = (await t.db.findings.list(ORG))[0];
    const sim = await t.analyst.post('/api/v1/remediations/simulate', { findingId: f.id, kind: 'waf', targetRef: 'api-gateway', params: { rule: { name: 'block-sqli', action: 'block', match: 'regex:union select' } } }).expect(201);
    const tr = (await t.viewer.get(`/api/v1/findings/${f.id}/trace`).expect(200)).body;
    expect(tr.scan.reportRef).toMatch(/^reports\//);
    expect(tr.plans[0].id).toBe(sim.body.plan.id);
    expect(sim.body.plan.terraform).toContain('aws_wafv2_rule_group');
  });
});

async function seedCredential() {
  t.analyst; // keep
  const r = await t.analyst.post('/api/v1/scans/ingest', { format: 'secrets', source: 'gl', report: { findings: [{ rule: 'aws', secret: AWS, file: 'a.js', repo: 'payments', verified: true }] } });
  const cred = (await t.db.credentials.list(ORG))[0];
  t.secrets.seed(cred.id);
  return { cred, r };
}

describe('zero-downtime rotation', () => {
  it('rotates, health-checks, and revokes the old key only after approval', async () => {
    const { cred } = await seedCredential();
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await settle();
    let ex = (await t.viewer.get(`/api/v1/executions/${rot.body.executionId}`)).body;
    expect(ex.status).toBe('awaiting_approval');
    expect(ex.steps.map((s: any) => s.status)).toEqual(['succeeded', 'succeeded', 'succeeded', 'awaiting_approval']);
    // Both versions valid while waiting: consumers already on v2, v1 is the fallback.
    expect(await t.secrets.getActive(cred.id)).toBe(2);
    expect(await t.secrets.isValid(cred.id, 1)).toBe(true);
    expect(t.health.checks).toEqual(['payments:2']);

    const inbox = (await t.approver.get('/api/v1/approvals?status=pending')).body;
    expect(inbox).toHaveLength(1);
    expect(inbox[0].plan.diff).toContain('revoke the previous credential version');
    await t.approver.post(`/api/v1/approvals/${inbox[0].id}/decision`, { decision: 'approved', comment: 'ok' }).expect(200);
    await settle();
    ex = (await t.viewer.get(`/api/v1/executions/${rot.body.executionId}`)).body;
    expect(ex.status).toBe('succeeded');
    expect(await t.secrets.isValid(cred.id, 1)).toBe(false);
    expect(await t.secrets.isValid(cred.id, 2)).toBe(true);
  });

  it('rolls back and never revokes when the new credential is unhealthy', async () => {
    const { cred } = await seedCredential();
    t.health.failFor.add(`${cred.id}:2`);
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await settle();
    const ex = (await t.viewer.get(`/api/v1/executions/${rot.body.executionId}`)).body;
    expect(ex.status).toBe('failed');
    expect(ex.steps[2].error).toContain('rolled back');
    expect(ex.steps[3].status).toBe('skipped');
    expect(await t.secrets.getActive(cred.id)).toBe(1);
    expect(await t.secrets.isValid(cred.id, 1)).toBe(true);
    expect((await t.db.approvals.list(ORG))).toHaveLength(0); // never even asked to revoke
  });

  it('rejection leaves the old credential untouched', async () => {
    const { cred } = await seedCredential();
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await settle();
    const [a] = (await t.db.approvals.list(ORG));
    await t.approver.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'rejected' }).expect(200);
    await settle();
    expect((await t.viewer.get(`/api/v1/executions/${rot.body.executionId}`)).body.status).toBe('rejected');
    expect(await t.secrets.isValid(cred.id, 1)).toBe(true);
    await t.approver.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'approved' }).expect(409); // decisions are final
  });
});

describe('engine resilience', () => {
  it('survives a worker crash after a side effect without duplicating it', async () => {
    const { cred } = await seedCredential();
    const orig = t.secrets.setActive.bind(t.secrets); let crashed = false;
    t.secrets.setActive = async (id, v) => { await orig(id, v); if (!crashed) { crashed = true; throw new Error('worker killed'); } };
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await settle();
    expect(crashed).toBe(true);
    expect([...t.secrets.versions.get(cred.id)!.keys()]).toEqual([1, 2]); // exactly one new version
    const ex = (await t.db.executions.get(ORG, rot.body.executionId))!;
    expect(ex.status).toBe('awaiting_approval');
    expect(ex.steps[1].status).toBe('succeeded');
    expect(await t.secrets.getActive(cred.id)).toBe(2);
  });

  it('a restarted worker resumes from persisted state (idempotent advance)', async () => {
    const { cred } = await seedCredential();
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await settle();
    await t.engine.advance(ORG, rot.body.executionId); // replay
    await t.engine.advance(ORG, rot.body.executionId);
    expect([...t.secrets.versions.get(cred.id)!.keys()]).toEqual([1, 2]);
    expect((await t.db.approvals.list(ORG))).toHaveLength(1);
  });

  it('two workers racing on one execution never double-apply (execution lock)', async () => {
    const { cred } = await seedCredential();
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await settle();
    const [a] = (await t.db.approvals.list(ORG));
    await t.approver.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'approved' }).expect(200);
    const results = await Promise.allSettled([t.engine.advance(ORG, rot.body.executionId), t.engine.advance(ORG, rot.body.executionId), t.engine.advance(ORG, rot.body.executionId)]);
    await settle();
    expect(results.some((r) => r.status === 'rejected' && /another worker/.test(String((r as any).reason)))).toBe(true);
    expect(t.secrets.calls.filter((c) => c.startsWith('revoke'))).toEqual(['revoke:1']);
    expect((await t.db.executions.get(ORG, rot.body.executionId))!.status).toBe('succeeded');
  });

  it('gives up after bounded retries and marks the execution failed', async () => {
    const { cred } = await seedCredential();
    t.secrets.createVersion = async () => { throw new Error('vault down'); };
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await settle();
    await t.engine.advance(ORG, rot.body.executionId).catch(() => {});
    await t.engine.advance(ORG, rot.body.executionId).catch(() => {});
    await t.engine.advance(ORG, rot.body.executionId).catch(() => {});
    await t.engine.advance(ORG, rot.body.executionId).catch(() => {});
    const ex = (await t.db.executions.get(ORG, rot.body.executionId))!;
    expect(ex.status).toBe('failed');
    expect(await t.secrets.getActive(cred.id)).toBe(1);
  });
});

describe('dry-run simulation & approval gate', () => {
  const iam = { roleName: 'billing-role', critical: true, grantedActions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 'iam:*'], auditEvents: ['s3:GetObject', 's3:GetObject'], resources: ['arn:aws:s3:::billing/*'] };

  it('simulation has zero effect on infrastructure', async () => {
    const r = await t.analyst.post('/api/v1/remediations/simulate', { kind: 'waf', targetRef: 'gw', params: { rule: { name: 'x' } } }).expect(201);
    await t.analyst.post('/api/v1/iam/audit-roles', { ...iam, submitForApproval: false }).expect(201);
    await settle();
    expect(t.infra.applied).toEqual([]);
    expect(r.body.plan.applied).toBe(false);
  });

  it('IAM trimming of a critical role waits for the signed decision, then applies exactly the approved plan', async () => {
    const r = await t.analyst.post('/api/v1/iam/audit-roles', { ...iam, submitForApproval: true }).expect(201);
    expect(r.body.audit.unused).toEqual(['iam:*', 's3:DeleteObject', 's3:PutObject']);
    expect(r.body.plan.diff).toContain('- iam:*');
    await settle();
    expect(t.infra.applied).toEqual([]);
    expect((await t.db.executions.get(ORG, r.body.executionId))!.status).toBe('awaiting_approval');
    const [a] = (await t.db.approvals.list(ORG));
    expect(a.planHash).toBe(r.body.plan.planHash);
    await t.approver.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'approved' }).expect(200);
    await settle();
    expect(t.infra.applied).toHaveLength(1);
    expect((await t.db.plans.get(ORG, r.body.plan.id))!.applied).toBe(true);
    const signed = (await t.db.approvals.get(ORG, a.id))!;
    expect(signed.signature).toMatch(/^[0-9a-f]{64}$/);
  });

  it('separation of duties: a requester holding approver rights cannot self-approve', async () => {
    const admin = t.as('admin-key');
    const r = await admin.post('/api/v1/iam/audit-roles', { ...iam, submitForApproval: true }).expect(201);
    await settle();
    const [a] = (await t.db.approvals.list(ORG));
    await admin.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'approved' }).expect(403);
    expect(t.infra.applied).toEqual([]);
    expect(r.body.executionId).toBeTruthy();
  });

  it('refuses to execute a plan tampered with after approval was requested', async () => {
    const r = await t.analyst.post('/api/v1/iam/audit-roles', { ...iam, submitForApproval: true }).expect(201);
    await settle();
    const [a] = (await t.db.approvals.list(ORG));
    (await t.db.plans.update(ORG, r.body.plan.id, (p) => { p.params = { ...p.params, evil: true }; }));
    await t.approver.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'approved' }).expect(200);
    await settle();
    expect(t.infra.applied).toEqual([]);
    expect((await t.db.executions.get(ORG, r.body.executionId))!.status).toBe('failed');
  });

  it('forged approvals cannot unlock adapters', async () => {
    const r = await t.analyst.post('/api/v1/iam/audit-roles', { ...iam, submitForApproval: true }).expect(201);
    await settle();
    const [a] = (await t.db.approvals.list(ORG));
    (await t.db.approvals.update(ORG, a.id, { status: 'approved', decidedBy: 'u_attacker', decidedAt: new Date().toISOString(), signature: 'f'.repeat(64) }));
    await t.engine.advance(ORG, r.body.executionId);
    expect(t.infra.applied).toEqual([]);
    expect((await t.db.executions.get(ORG, r.body.executionId))!.status).toBe('failed');
    await expect(t.infra.isolateService('x', undefined as any)).rejects.toThrow(/approval proof/);
  });
});

describe('incident response (SOAR)', () => {
  const trig = { kind: 'brute_force', source: '203.0.113.9', target: 'auth-api', count: 900, windowSec: 60, gatewayLogs: ['401 POST /login 203.0.113.9 password=hunter2hunter2', '401 POST /login 203.0.113.9'] };

  it('ignores traffic below threshold', async () => {
    const r = await t.analyst.post('/api/v1/incidents/trigger', { ...trig, count: 3 }).expect(202);
    expect(r.body.triggered).toBe(false);
  });

  it('freezes evidence immediately, summarises with citations, and isolates only after approval', async () => {
    const r = await t.analyst.post('/api/v1/incidents/trigger', trig).expect(202);
    expect(r.body).toMatchObject({ triggered: true, severity: 'critical' });
    await settle();
    expect(t.infra.applied).toEqual([]);
    const f = (await t.viewer.get(`/api/v1/executions/${r.body.executionId}/forensics`).expect(200)).body;
    expect(f.snapshot.integrity).toBe('verified');
    expect(f.evidence.logs).toHaveLength(2);
    expect(JSON.stringify(f)).not.toContain('hunter2hunter2');
    expect(f.incident.summary).toMatch(/\[ev-log-1\]/);

    const [a] = (await t.db.approvals.list(ORG));
    await t.approver.post(`/api/v1/approvals/${a.id}/decision`, { decision: 'approved' }).expect(200);
    await settle();
    expect(t.infra.applied).toEqual([{ op: 'isolate', arg: 'auth-api' }]);
    const ex = (await t.db.executions.get(ORG, r.body.executionId))!;
    expect(ex.status).toBe('succeeded');
    expect((await t.viewer.get(`/api/v1/incidents/${r.body.incidentId}`)).body.status).toBe('contained');
  });

  it('detects tampering of the frozen evidence', async () => {
    const r = await t.analyst.post('/api/v1/incidents/trigger', trig);
    await settle();
    const snap = (await t.db.snapshots.list(ORG))[0];
    await t.storage.put(snap.objectKey, '{"forged":true}');
    await t.viewer.get(`/api/v1/executions/${r.body.executionId}/forensics`).expect(400);
  });

  it('validates the webhook schema strictly', async () => {
    await t.analyst.post('/api/v1/incidents/trigger', { ...trig, target: undefined }).expect(400);
    await t.analyst.post('/api/v1/incidents/trigger', { ...trig, callbackUrl: 'http://169.254.169.254' }).expect(400);
  });
});

describe('audit & workflow versions', () => {
  it('keeps a verifiable audit chain across a full flow', async () => {
    const { cred } = await seedCredential();
    await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id });
    await settle();
    const a = (await t.viewer.get('/api/v1/audit')).body;
    expect(a.verify.ok).toBe(true);
    expect(a.entries.map((e: any) => e.event)).toEqual(expect.arrayContaining(['scan.ingested', 'execution.started', 'approval.requested']));
  });
  it('published workflows are versioned and destructive steps must be gated', async () => {
    const { WorkflowService } = await import('../src/workflow/workflow.service');
    const svc = t.app.get(WorkflowService);
    const v1 = await svc.resolve(ORG, 'waf-remediation');
    await expect(svc.publish(ORG, 'custom', [{ name: 's', action: 'isolate_service' }])).rejects.toThrow(/destructive/);
    const v2 = await svc.publish(ORG, 'waf-remediation', [{ name: 'apply-waf-rule', action: 'apply_waf_rule', destructive: true }]);
    expect(v2.version).toBe(v1.version + 1);
    const racers = await Promise.all([1, 2, 3].map(() => svc.publish(ORG, 'waf-remediation', [{ name: 'apply-waf-rule', action: 'apply_waf_rule', destructive: true }])));
    expect(new Set(racers.map((w) => w.version)).size).toBe(3);            // concurrent publishers each get a distinct version
    expect((await t.db.workflows.get(ORG, v1.id))!.version).toBe(1);
  });
});

describe('read APIs for the console & hardening', () => {
  it('lists/filters findings, credentials, executions, incidents and enriches the approval inbox', async () => {
    await t.analyst.post('/api/v1/scans/ingest', { format: 'sarif', source: 'ci', report: sarif([res('js/sql-injection', 'api/x.js'), res('js/xss', 'web/y.js', 'XSS', 'warning')]) });
    const { cred } = await seedCredential();
    const rot = await t.analyst.post('/api/v1/secrets/rotate', { credentialId: cred.id }).expect(202);
    await t.analyst.post('/api/v1/incidents/trigger', { kind: 'brute_force', source: '1.2.3.4', target: 'auth-api', count: 900, windowSec: 60 });
    await settle();
    expect((await t.viewer.get('/api/v1/me')).body).toMatchObject({ role: 'viewer', orgId: ORG });
    const f = (await t.viewer.get('/api/v1/findings?severity=critical,high&q=sql')).body;
    expect(f.total).toBeGreaterThan(0); expect(f.items.every((x: any) => /sql/i.test(x.title + x.ruleId))).toBe(true);
    expect((await t.viewer.get('/api/v1/findings?kind=secret')).body.items[0].maskedSecret).toBe('AKIA****LE');
    expect((await t.viewer.get('/api/v1/findings?limit=1&offset=1')).body.items).toHaveLength(1);
    expect((await t.viewer.get('/api/v1/credentials')).body[0].maskedValue).toBe('AKIA****LE');
    expect((await t.viewer.get('/api/v1/executions')).body.length).toBe(2);
    expect((await t.viewer.get('/api/v1/incidents')).body[0]).toMatchObject({ target: 'auth-api', anomaly: { source: '1.2.3.4' } });
    const inbox = (await t.viewer.get('/api/v1/approvals?status=pending')).body;
    expect(inbox).toHaveLength(2);
    expect(inbox.find((a: any) => a.execution.id === rot.body.executionId).execution.steps.map((s: any) => s.status)).toEqual(['succeeded', 'succeeded', 'succeeded', 'awaiting_approval']);
    await t.other.get('/api/v1/credentials').expect(200).then((r) => expect(r.body).toEqual([]));
  });
  it('sends hardening headers, exposes /healthz, and rate-limits per credential', async () => {
    const r = await t.http.get('/healthz').expect(200);
    expect(r.headers['x-content-type-options']).toBe('nosniff'); expect(r.headers['cache-control']).toBe('no-store'); expect(r.headers['x-powered-by']).toBeUndefined();
    process.env.RATE_LIMIT_PER_MIN = '3';
    const t2 = await boot();
    for (let i = 0; i < 3; i++) await t2.viewer.get('/api/v1/me').expect(200);
    const blocked = await t2.viewer.get('/api/v1/me').expect(429);
    expect(blocked.headers['retry-after']).toBeDefined();
    await t2.analyst.get('/api/v1/me').expect(200); // other credential unaffected
    delete process.env.RATE_LIMIT_PER_MIN; await t2.app.close();
  });
});
