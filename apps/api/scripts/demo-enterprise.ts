/**
 * Reproducible end-to-end laboratory demo (in-memory, simulated ports, NO external service is contacted):
 *   npm run demo:enterprise -w apps/api
 * The "security source" is a clearly labelled SIMULATOR (source `sim-edr`), not a real EDR. Every step asserts its outcome and the script exits non-zero if any fails.
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { AppModule } from '../src/app.module';

for (const k of ['REDIS_URL', 'DATABASE_URL', 'OBJECT_STORE_BUCKET', 'INFRA_MODE', 'ANALYTICS_URL', 'OIDC_ISSUER', 'MESH_ENFORCE_TENANT']) delete process.env[k];
process.env.PLATFORM_ADMIN_EMAIL = 'root@platform.lab'; process.env.PLATFORM_ADMIN_PASSWORD = 'Lab-Platform-Pass-1!x'; process.env.RATE_LIMIT_PER_MIN = '0';
const PW = 'Lab-User-Pass-2026!x';
let n = 0;
const step = (title: string) => console.log(`\n${String(++n).padStart(2, '0')}. ${title}`);
const ok = (cond: unknown, what: string) => { if (!cond) throw new Error(`ASSERTION FAILED: ${what}`); console.log(`    ✔ ${what}`); };

(async () => {
  const app = await NestFactory.create(AppModule, { logger: false }); await app.listen(0);
  const base = `http://127.0.0.1:${new URL((await app.getUrl()).replace('[::1]', '127.0.0.1')).port}/api/v1`;
  const call = async (tok: string, method: string, path: string, body?: unknown, raw = false) => {
    const r = await fetch(base + path, { method, headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    if (raw) return Buffer.from(await r.arrayBuffer());
    const j: any = await r.json().catch(() => ({})); if (!r.ok) throw new Error(`${method} ${path} → ${r.status} ${JSON.stringify(j)}`); return j;
  };
  const login = async (org: string, email: string, password: string) => (await (await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ org, email, password }) })).json() as any).accessToken as string;

  step('Create an organisation (platform administrator)');
  const plat = await login('org_platform', 'root@platform.lab', 'Lab-Platform-Pass-1!x');
  await call(plat, 'POST', '/platform/orgs', { id: 'org_lab', name: 'Laboratorio SentinelMesh', plan: 'enterprise', adminEmail: 'admin@lab.test', adminPassword: PW });
  const admin = await login('org_lab', 'admin@lab.test', PW);
  for (const [email, role] of [['analyst@lab.test', 'analyst'], ['approver@lab.test', 'approver']]) await call(admin, 'POST', '/users', { email, password: PW, role });
  const analyst = await login('org_lab', 'analyst@lab.test', PW), approver = await login('org_lab', 'approver@lab.test', PW);
  ok(admin && analyst && approver, 'organisation, admin, analyst and approver exist and can sign in');

  step('Register test assets and relations');
  const web = await call(analyst, 'POST', '/inventory/assets', { type: 'server', identifier: 'web-01', criticality: 'critical', internetFacing: true, source: 'lab' });
  const db = await call(analyst, 'POST', '/inventory/assets', { type: 'database', identifier: 'ledger-db', criticality: 'critical', source: 'lab' });
  await call(analyst, 'POST', '/inventory/relations', { from: web.id, to: db.id, kind: 'depends_on', confidence: 0.9 });
  ok((await call(analyst, 'GET', '/inventory/assets')).total === 2, 'two assets in the inventory');

  step('Install playbooks and add one for the SIMULATOR source');
  await call(analyst, 'POST', '/soar/playbooks/install-defaults');
  await call(analyst, 'POST', '/soar/playbooks', { key: 'sim-edr-isolation', name: 'Simulated EDR detection → isolation proposal', owner: 'lab', mode: 'ASSISTED', trigger: { type: 'signal' }, conditions: [{ field: 'source', op: 'eq', value: 'sim-edr' }, { field: 'severity', op: 'gte', value: 'high' }],
    actions: [{ type: 'create_case', params: { name: '[SIMULATOR] Possible compromise of {{trigger.host}}' } }, { type: 'propose_endpoint_isolation', params: { target: '{{trigger.host}}', reason: '{{trigger.title}}' } }] });
  ok((await call(analyst, 'GET', '/soar/playbooks')).length >= 7, 'default playbooks plus the simulator playbook are published');

  step('Import a (test) vulnerability intelligence feed and detect a vulnerability on web-01');
  await call(analyst, 'POST', '/intel/import', { kind: 'kev', payload: { vulnerabilities: [{ cveID: 'CVE-2099-0001', dueDate: '2099-01-01' }] } });
  await call(analyst, 'POST', '/intel/import', { kind: 'nvd', payload: { vulnerabilities: [{ cve: { id: 'CVE-2099-0001', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, version: '3.1' } }] } } }] } });
  const vuln = await call(analyst, 'POST', '/vulns', { assetId: web.id, cve: 'CVE-2099-0001', title: '[TEST] remote code execution in web framework', confidence: 'confirmed', source: 'lab-scanner', evidence: ['lab PoC'] });
  ok(vuln.priority.level === 'immediate', `priority is IMMEDIATE: ${vuln.priority.explanation}`);

  step('Simulator sends detections; correlate them with the asset and its vulnerability');
  const t0 = new Date().toISOString();
  await call(analyst, 'POST', '/signals', { signals: [{ source: 'sim-edr', sourceId: 'sim-1', kind: 'detection', title: '[SIMULATOR] Credential dumping', severity: 'critical', host: 'web-01', at: t0, cves: ['CVE-2099-0001'] }] });
  await call(analyst, 'POST', '/signals', { signals: [{ source: 'sim-siem', sourceId: 'sim-2', kind: 'alert', title: '[SIMULATOR] Suspicious outbound connection', severity: 'high', host: 'web-01', at: t0 }] });
  const cor = (await call(analyst, 'GET', '/correlations'))[0];
  ok(cor && cor.status === 'probable' && cor.signalIds.length === 2, `one correlation, status "${cor?.status}" (a hypothesis), confidence ${cor?.confidence}`);

  step('A case was opened (incident management) and evidence is registered');
  const cases = (await call(analyst, 'GET', '/cases')).items; ok(cases.length >= 1, `${cases.length} case(s) open: ${cases.map((c: any) => `#${c.number} ${c.name}`).join(' | ')}`);
  const cs = cases.find((c: any) => c.source === 'correlation') ?? cases[0];
  const ev = await call(analyst, 'POST', `/cases/${cs.id}/evidence`, { name: 'web-01-auth.log', type: 'log', source: 'sim-edr', content: 'Nov 17 sshd[812]: Accepted publickey for root from 203.0.113.9\n' });
  ok(/^[0-9a-f]{64}$/.test(ev.sha256), `evidence hashed at capture (sha256 ${ev.sha256.slice(0, 16)}…)`);
  ok((await call(analyst, 'POST', `/evidence/${ev.id}/verify`)).intact, 'evidence integrity verified; custody log records the access');

  step('Priority and the explanation for the immediate risk');
  const pr = await call(analyst, 'GET', '/ctem/priorities'); ok(pr[0].priority.level === 'immediate', pr[0].priority.explanation);
  const paths = await call(analyst, 'GET', '/ctem/attack-paths'); ok(paths.length >= 1 && paths[0].status !== 'confirmed', `${paths.length} attack path(s) shown as ${paths[0]?.status} (never "confirmed intrusion")`);

  step('Remediation proposal and approval request');
  const run = (await call(analyst, 'GET', '/soar/runs')).find((r: any) => r.playbookKey === 'sim-edr-isolation');
  ok(run.status === 'awaiting_approval', `run ${run.id} proposes endpoint isolation and waits for a human`);
  const pend = (await call(approver, 'GET', '/soar/approvals')).find((a: any) => a.runId === run.id); ok(pend.action === 'propose_endpoint_isolation' && (await call(admin, 'GET', `/soar/runs/${run.id}`)).effects.length === 0, 'nothing has been executed yet');

  step('Approve (a different person than the requester) and execute the safe LAB action');
  await call(approver, 'POST', `/approvals/${pend.approvalId}/decision`, { decision: 'approved', comment: 'Lab approval' });
  const done = await call(admin, 'GET', `/soar/runs/${run.id}`);
  ok(done.run.status === 'completed' && done.effects[0]?.action === 'propose_endpoint_isolation', 'step executed by the LAB executor: recorded, no real system touched');

  step('Result recorded in the case timeline');
  const tl = await call(analyst, 'GET', `/cases/${(await call(analyst, 'GET', '/cases')).items.find((c: any) => c.source === 'playbook')?.id ?? cs.id}/timeline`); ok(tl.length >= 2, `timeline has ${tl.length} entries`);

  step('Generate the PDF report');
  const rep = await call(analyst, 'POST', '/reports', { kind: 'incident', caseId: cs.id });
  const pdf = await call(analyst, 'GET', `/reports/${rep.id}/pdf`, undefined, true);
  ok(pdf.subarray(0, 5).toString() === '%PDF-', `incident report PDF generated (${pdf.length} bytes, sha256 ${rep.sha256.slice(0, 16)}…)`);
  await call(analyst, 'POST', '/reports', { kind: 'executive' });
  const out = join(process.cwd(), 'demo-incident-report.pdf'); writeFileSync(out, pdf); console.log(`    (written to ${out})`);

  step('Review the complete audit trail');
  const audit = await call(admin, 'GET', '/audit');
  const events = new Set((audit.entries as any[]).map((e) => e.event));
  ok(audit.verify.ok, `hash chain verifies (${audit.entries.length} entries)`);
  for (const e of ['asset.discovered', 'vuln.created', 'correlation.created', 'case.opened', 'evidence.captured', 'playbook.run_started', 'approval.requested', 'approval.approved', 'playbook.step_executed', 'report.generated']) ok(events.has(e), `audit contains ${e}`);

  console.log('\nDEMO COMPLETE — all assertions passed. Simulated source: sim-edr / sim-siem. Executor: lab.\n');
  await app.close(); process.exit(0);
})().catch((e) => { console.error(`\nDEMO FAILED: ${e.message}`); process.exit(1); });
