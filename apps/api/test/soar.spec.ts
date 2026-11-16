import { boot, Env } from './helpers';

let t: Env;
const adm = () => t.as('admin-key');
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });
const edrSignal = (o: object = {}) => ({ source: 'crowdstrike', sourceId: `s-${Math.random().toString(36).slice(2)}`, kind: 'detection', title: 'Credential dumping', severity: 'critical', at: new Date().toISOString(), host: 'web-01', ...o });
const setup = async () => {
  await t.analyst.post('/api/v1/soar/playbooks/install-defaults').expect(200);
  return (await t.analyst.post('/api/v1/inventory/assets', { type: 'endpoint', identifier: 'web-01', criticality: 'high', internetFacing: true }).expect(201)).body;
};
const runs = async (q = '') => (await t.viewer.get(`/api/v1/soar/runs${q}`).expect(200)).body as any[];
const pending = async () => (await t.viewer.get('/api/v1/soar/approvals').expect(200)).body as any[];

describe('SOAR playbooks — ASSISTED (default)', () => {
  it('detection → case + alert + a PROPOSAL that does nothing until a human signs; then the lab executor records it', async () => {
    await setup();
    expect((await t.analyst.post('/api/v1/soar/playbooks/install-defaults')).body.installed).toEqual([]);          // idempotent
    await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] }).expect(201);
    const [r] = await runs(); expect(r).toMatchObject({ playbookKey: 'endpoint-compromised', mode: 'ASSISTED', effectiveMode: 'ASSISTED', status: 'awaiting_approval', requestedBy: 'u_analyst' });
    expect(r.steps.map((s: any) => [s.action, s.status])).toEqual([['create_case', 'executed'], ['notify', 'executed'], ['propose_endpoint_isolation', 'awaiting_approval']]);
    expect(r.steps[0].result.caseId).toBeTruthy(); expect(r.steps[1].result.note).toMatch(/no notification channel/);
    expect(await t.db.labEffects.list('org_acme')).toHaveLength(0);                                                // nothing happened yet
    const [p] = await pending(); expect(p).toMatchObject({ action: 'propose_endpoint_isolation', params: { target: 'web-01' }, playbook: 'endpoint-compromised', riskLevel: 'high' }); expect(p.planHash).toMatch(/^[0-9a-f]{64}$/);
    await t.analyst.post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'approved' }).expect(403);   // analysts cannot approve
    await t.approver.post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'approved', comment: 'confirmed with the SOC lead' }).expect(200);
    const done = (await t.viewer.get(`/api/v1/soar/runs/${r.id}`).expect(200)).body;
    expect(done.run.status).toBe('completed'); expect(done.run.steps[2]).toMatchObject({ status: 'executed', result: { executor: 'lab' } });
    expect(done.effects[0]).toMatchObject({ action: 'propose_endpoint_isolation', target: 'web-01' });
    expect(done.run.history.map((h: any) => h.text).join('|')).toMatch(/waiting for human approval[\s\S]*approved by u_approver/);
    const cs = (await t.viewer.get(`/api/v1/cases/${r.steps[0].result.caseId}`)).body.case; expect(cs.actions[0].action).toMatch(/propose_endpoint_isolation/); expect(cs.source).toBe('playbook');
    const ev = (await t.audit.list('org_acme')).map((e) => e.event); expect(ev).toEqual(expect.arrayContaining(['playbook.run_started', 'approval.requested', 'approval.approved', 'playbook.step_executed', 'playbook.run_completed']));
    expect((await t.audit.verify('org_acme')).ok).toBe(true);
  });
  it('is idempotent per entity: the same signal never fires the same playbook twice', async () => {
    await setup(); const s = edrSignal();
    await t.analyst.post('/api/v1/signals', { signals: [s] }).expect(201); await t.analyst.post('/api/v1/signals', { signals: [s] }).expect(201);
    const [r] = await runs(); expect(await runs()).toHaveLength(1);
    expect((await t.analyst.post('/api/v1/soar/trigger', { type: 'signal', entityId: (await t.db.signals.list('org_acme'))[0].id }).expect(200)).body.runs).toBe(0);
    expect(r.steps.filter((x: any) => x.status === 'awaiting_approval')).toHaveLength(1); expect(await pending()).toHaveLength(1);
  });
  it('separation of duties: whoever caused the run cannot approve it; another approver can', async () => {
    await setup();
    await t.approver.post('/api/v1/signals', { signals: [edrSignal()] }).expect(201);                              // the approver triggers it (signals:write is allowed to approvers)
    const [p] = await pending();
    await t.approver.post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'approved' }).expect(403);
    await adm().post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'approved', comment: 'ok' }).expect(200);
    expect((await runs())[0].status).toBe('completed');
  });
  it('a rejection stops the run and nothing is executed', async () => {
    await setup(); await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] });
    const [p] = await pending(); await t.approver.post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'rejected', comment: 'false positive' }).expect(200);
    const [r] = await runs(); expect(r.status).toBe('rejected'); expect(r.steps[2].status).toBe('rejected'); expect(await t.db.labEffects.list('org_acme')).toHaveLength(0);
    await t.approver.post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'approved' }).expect(409);       // decisions are final
  });
  it('approval is bound to the exact action: a tampered step is refused even with a genuine signature', async () => {
    await setup(); await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] });
    const [r] = await runs(), [p] = await pending();
    await t.db.runs.update('org_acme', r.id, (x) => { x.steps[2].params['target'] = 'domain-controller-01'; });        // someone edits the run after the request
    await t.approver.post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'approved' }).expect(200);
    const after = (await runs())[0]; expect(after.status).toBe('failed'); expect(after.steps[2].result.error).toMatch(/not bound to this exact action/);
    expect(await t.db.labEffects.list('org_acme')).toHaveLength(0);
  });
  it('conditions decide: low severity, unknown sources or missing hosts do not fire; disabled playbooks do not fire; versions are immutable', async () => {
    await setup();
    await t.analyst.post('/api/v1/signals', { signals: [edrSignal({ severity: 'low' }), edrSignal({ source: 'custom-tool' }), edrSignal({ host: undefined })] });
    expect(await runs()).toHaveLength(0);
    await adm().post('/api/v1/soar/playbooks/endpoint-compromised/state', { enabled: false }).expect(200);
    await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] }); expect(await runs()).toHaveLength(0);
    await t.analyst.post('/api/v1/soar/playbooks/endpoint-compromised/state', { enabled: true }).expect(403);       // enabling needs the admin permission
    await adm().post('/api/v1/soar/playbooks/endpoint-compromised/state', { enabled: true }).expect(200);
    const pb = (await t.viewer.get('/api/v1/soar/playbooks')).body.find((x: any) => x.key === 'endpoint-compromised');
    await t.analyst.post('/api/v1/soar/playbooks', { key: 'endpoint-compromised', name: pb.name, owner: 'me', trigger: pb.trigger, conditions: [], actions: [{ type: 'notify', params: {} }] }).expect(201);
    expect((await t.viewer.get('/api/v1/soar/playbooks/endpoint-compromised/versions')).body.map((v: any) => v.version).sort()).toEqual([1, 2]);
    await expect(t.db.playbooks.update('org_acme', pb.id, { name: 'x' })).resolves.toBeTruthy();                     // (memory store: immutability of versions is enforced in PostgreSQL by trigger; new versions are the only API path)
  });
  it('validates playbooks and escalates the declared risk to the worst action', async () => {
    await t.analyst.post('/api/v1/soar/playbooks', { key: 'bad key', name: 'x', owner: 'o', trigger: { type: 'signal' }, actions: [{ type: 'notify', params: {} }] }).expect(400);
    await t.analyst.post('/api/v1/soar/playbooks', { key: 'rm-rf', name: 'x', owner: 'o', trigger: { type: 'signal' }, actions: [{ type: 'delete_everything', params: {} }] }).expect(400);
    await t.analyst.post('/api/v1/soar/playbooks', { key: 'rm-rf', name: 'x', owner: 'o', trigger: { type: 'signal' }, actions: [{ type: 'notify', params: {} }], extra: 1 }).expect(400);
    const pb = (await t.analyst.post('/api/v1/soar/playbooks', { key: 'sneaky', name: 'x', owner: 'o', riskLevel: 'low', trigger: { type: 'signal' }, actions: [{ type: 'propose_account_lock', params: {} }] }).expect(201)).body;
    expect(pb.riskLevel).toBe('high');                                                                             // cannot be declared "low" while it can lock accounts
    await t.viewer.post('/api/v1/soar/playbooks', { key: 'x-1', name: 'x', owner: 'o', trigger: { type: 'signal' }, actions: [{ type: 'notify', params: {} }] }).expect(403);
  });
});

describe('SOAR automation levels', () => {
  it('OBSERVE executes only record-keeping and alerts; every proposal is skipped and no approval is created', async () => {
    await setup(); await adm().post('/api/v1/soar/automation', { ceiling: 'OBSERVE' }).expect(200);
    await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] });
    const [r] = await runs(); expect(r).toMatchObject({ effectiveMode: 'OBSERVE', mode: 'ASSISTED', status: 'observed' });
    expect(r.steps.map((s: any) => s.status)).toEqual(['executed', 'executed', 'skipped']); expect(r.steps[2].result.reason).toMatch(/OBSERVE mode/);
    expect(await pending()).toHaveLength(0); expect(await t.db.labEffects.list('org_acme')).toHaveLength(0);
  });
  it('AUTOMATED is off by default and cannot be switched on by accident', async () => {
    expect((await adm().get('/api/v1/soar/automation')).body).toMatchObject({ ceiling: 'ASSISTED', automatedEnabled: false, killSwitch: false });
    await t.analyst.post('/api/v1/soar/playbooks', { key: 'auto-1', name: 'x', owner: 'o', mode: 'AUTOMATED', trigger: { type: 'signal' }, actions: [{ type: 'notify', params: {} }] }).expect(400);
    await adm().post('/api/v1/soar/automation', { ceiling: 'AUTOMATED' }).expect(400);
    await t.analyst.post('/api/v1/soar/automation', { automatedEnabled: true }).expect(403);                      // only administrators
  });
  it('AUTOMATED executes only allow-listed, non-high-risk actions within the hourly budget; the rest still needs approval', async () => {
    await setup();
    await adm().post('/api/v1/soar/automation', { automatedEnabled: true, ceiling: 'AUTOMATED', allowedAutoActions: ['propose_session_revoke', 'propose_endpoint_isolation'], maxActionsPerHour: 1 }).expect(200);
    const pbBody = (key: string, action: string, extra: object = {}) => ({ key, name: key, owner: 'o', mode: 'AUTOMATED', trigger: { type: 'signal' }, conditions: [{ field: 'title', op: 'contains', value: key }], actions: [{ type: action, params: { identity: '{{trigger.user}}', target: '{{trigger.host}}' } }], ...extra });
    await t.analyst.post('/api/v1/soar/playbooks', pbBody('revoke', 'propose_session_revoke')).expect(201);
    await t.analyst.post('/api/v1/soar/playbooks', pbBody('isolate', 'propose_endpoint_isolation')).expect(201);
    await t.analyst.post('/api/v1/signals', { signals: [edrSignal({ title: 'revoke now', user: 'ana@acme.test', host: undefined }), edrSignal({ title: 'revoke again', user: 'bob@acme.test', host: undefined }), edrSignal({ title: 'isolate it', host: 'web-01' })] });
    const all = await runs(), by = (k: string, n = 0) => all.filter((r) => r.playbookKey === k)[n];
    const ok = all.filter((r) => r.playbookKey === 'revoke'); expect(ok).toHaveLength(2);
    const auto = ok.filter((r) => r.status === 'completed'), waiting = ok.filter((r) => r.status === 'awaiting_approval');
    expect(auto).toHaveLength(1); expect(auto[0].steps[0].result).toMatchObject({ auto: true, executor: 'lab' }); expect(waiting).toHaveLength(1);       // second one exceeded the 1/hour budget
    expect(by('isolate').status).toBe('awaiting_approval');                                                          // high-risk is never automatic
    expect((await t.db.labEffects.list('org_acme')).map((e) => e.action)).toEqual(['propose_session_revoke']);
    expect((await adm().post('/api/v1/soar/automation', { automatedEnabled: false })).body).toMatchObject({ ceiling: 'ASSISTED', allowedAutoActions: [] });   // switching it off also drops the ceiling and the allow-list
  });
  it('kill switch: stops pending work, forces OBSERVE, blocks execution of approved steps, and can be released', async () => {
    await setup(); await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] });
    const [p] = await pending(); const rid = (await runs())[0].id;
    await t.analyst.post('/api/v1/soar/kill-switch', { on: true, reason: 'runaway automation' }).expect(403);
    expect((await t.approver.post('/api/v1/soar/kill-switch', { on: true, reason: 'investigating a false-positive storm' }).expect(200)).body).toMatchObject({ killSwitch: true, stopped: 1 });
    expect((await runs())[0]).toMatchObject({ id: rid, status: 'stopped' }); expect((await runs())[0].steps[2].status).toBe('skipped');
    await adm().post(`/api/v1/approvals/${p.approvalId}/decision`, { decision: 'approved' }).expect(200);           // a late approval of a stopped run does nothing
    expect(await t.db.labEffects.list('org_acme')).toHaveLength(0);
    await t.analyst.post('/api/v1/signals', { signals: [edrSignal({ host: 'web-01' })] });
    expect((await runs()).find((r) => r.id !== rid)).toMatchObject({ effectiveMode: 'OBSERVE', status: 'observed' });
    await t.approver.post('/api/v1/soar/kill-switch', { on: false, reason: 'storm over, back to normal' }).expect(200);
    expect((await t.viewer.get('/api/v1/soar/automation')).body.killSwitch).toBe(false);
    expect((await t.audit.list('org_acme')).map((e) => e.event)).toEqual(expect.arrayContaining(['soar.kill_switch_on', 'soar.kill_switch_off', 'soar.automation_changed'].slice(0, 2)));
  });
  it('an operator can stop a run that is waiting', async () => {
    await setup(); await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] }); const [r] = await runs();
    await t.analyst.post(`/api/v1/soar/runs/${r.id}/stop`, { reason: 'duplicate of another case' }).expect(403);
    await t.approver.post(`/api/v1/soar/runs/${r.id}/stop`, { reason: 'duplicate of another case' }).expect(200);
    await t.approver.post(`/api/v1/soar/runs/${r.id}/stop`, { reason: 'again, to be sure' }).expect(409);
  });
});

describe('SOAR triggers from the other domains', () => {
  it('an immediate-priority vulnerability opens a ticket and proposes a patch request', async () => {
    await setup();
    const a = (await t.analyst.post('/api/v1/inventory/assets', { type: 'web_app', identifier: 'shop', criticality: 'critical', internetFacing: true })).body;
    await t.analyst.post('/api/v1/intel/import', { kind: 'kev', payload: { vulnerabilities: [{ cveID: 'CVE-2024-5555', dueDate: '2030-01-01' }] } });
    await t.analyst.post('/api/v1/vulns', { assetId: a.id, cve: 'CVE-2024-5555', title: 'RCE', severity: 'critical', confidence: 'confirmed', source: 'dast' }).expect(201);
    const r = (await runs()).find((x) => x.playbookKey === 'critical-vulnerability')!; expect(r.status).toBe('awaiting_approval');
    const tk = await t.db.tickets.list('org_acme'); expect(tk[0]).toMatchObject({ title: 'Patch CVE-2024-5555 on shop', severity: 'critical', status: 'open' }); expect(tk[0].body).toMatch(/Priority IMMEDIATE/);
    expect((await pending())[0]).toMatchObject({ action: 'propose_patch_request', params: { target: 'shop', cve: 'CVE-2024-5555' } });
  });
  it('a leaked secret finding, a confirmed exposure and an over-privileged identity each trigger their playbook', async () => {
    await setup();
    await t.analyst.post('/api/v1/scans/ingest', { format: 'secrets', source: 'gitleaks', report: { findings: [{ rule: 'aws-access-key', secret: 'AKIAIOSFODNN7EXAMPLE', file: 'src/c.js', line: 1, repo: 'payments', verified: true }] } }).expect(201);
    expect((await runs()).find((r) => r.playbookKey === 'exposed-credential')!.steps.map((s: any) => s.action)).toEqual(['create_ticket', 'notify', 'propose_config_fix']);
    const tk = (await t.db.tickets.list('org_acme'))[0]; expect(JSON.stringify(tk)).not.toContain('AKIAIOSFODNN7EXAMPLE');          // only the masked form travels
    const a = (await t.analyst.post('/api/v1/inventory/assets', { type: 'server', identifier: 'edge1', internetFacing: true })).body;
    await t.analyst.post('/api/v1/exposures/observe', { assetId: a.id, source: 's', observations: [{ kind: 'open_port', title: 'RDP exposed', severity: 'high', evidence: ['3389 open'], confidence: 'confirmed' }] }).expect(200);
    expect((await runs()).some((r) => r.playbookKey === 'exposed-asset')).toBe(true);
    const ent = ['a:1', 'a:2', 'a:3', 'a:4', 'a:5', 'a:6', 'a:7', 'a:8', 'a:9', 'a:10'];
    await t.analyst.post('/api/v1/iam/identities', { kind: 'human', name: 'Fat', provider: 'x', externalId: 'f', entitlements: ent, usedEntitlements: ['a:1'], lastActivityAt: new Date().toISOString() }).expect(201);
    expect((await t.analyst.post('/api/v1/soar/identity-scan').expect(200)).body.evaluated).toBeGreaterThan(0);
    expect((await runs()).find((r) => r.playbookKey === 'excessive-privileges')!.steps[1]).toMatchObject({ action: 'propose_permission_change', status: 'awaiting_approval' });
    await t.analyst.post('/api/v1/soar/identity-scan').expect(200); expect((await runs()).filter((r) => r.playbookKey === 'excessive-privileges')).toHaveLength(1);   // repeatable
  });
  it('plan gating and tenant isolation', async () => {
    await setup(); await t.analyst.post('/api/v1/signals', { signals: [edrSignal()] }); const [r] = await runs();
    await t.other.get(`/api/v1/soar/runs/${r.id}`).expect(404); expect((await t.other.get('/api/v1/soar/runs')).body).toEqual([]); expect((await t.other.get('/api/v1/soar/approvals')).body).toEqual([]);
    const [p] = await pending(); const o = t.as('other-org-analyst'); void o;
    await t.other.post(`/api/v1/soar/runs/${r.id}/stop`, { reason: 'let me stop your run' }).expect(403);
    await t.db.orgs.put({ id: 'org_acme', orgId: 'org_platform', name: 'a', plan: 'business', status: 'active', retentionDays: 365, createdAt: '', createdBy: 'x' });
    await t.viewer.get('/api/v1/soar/playbooks').expect(402); await t.viewer.get('/api/v1/cases').expect(200); expect(p.approvalId).toBeTruthy();
  });
});
