/**
 * Controlled incident simulation. Boots the API in-process (in-memory queue, simulated cloud ports) and walks the
 * whole story: exposure → leaked key → zero-downtime rotation → brute-force incident → human approval → containment.
 *   npm run simulate                 # approver approves
 *   npm run simulate -- --reject     # approver rejects: nothing destructive happens
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { MemoryQueue, JOB_QUEUE } from '../src/queue/queue';
import { PORTS } from '../src/workflow/ports';
import { SimulatedInfra, SimulatedSecrets } from '../src/workflow/simulated';
import { Db } from '../src/store/db';

// These scripts are self-contained, in-memory demos: ignore any Redis/Postgres/S3/AWS settings left in the shell.
for (const k of ['REDIS_URL', 'DATABASE_URL', 'OBJECT_STORE_BUCKET', 'OBJECT_STORE_DIR', 'INFRA_MODE', 'ANALYTICS_URL', 'OIDC_ISSUER', 'MESH_ENFORCE_TENANT']) delete process.env[k];
process.env.HEALTH_RETRY_MS = '0';
const reject = process.argv.includes('--reject');
const say = (s: string) => console.log(`\n\x1b[36m▶ ${s}\x1b[0m`);
const show = (o: unknown) => console.log(JSON.stringify(o, null, 2).split('\n').map((l) => '   ' + l).join('\n'));

(async () => {
  const app = await NestFactory.create(AppModule, { logger: false });
  await app.listen(0);
  const base = (await app.getUrl()).replace('[::1]', 'localhost');
  const queue = app.get<MemoryQueue>(JOB_QUEUE); const secrets = app.get<SimulatedSecrets>(PORTS.SECRETS); const infra = app.get<SimulatedInfra>(PORTS.INFRA); const db = app.get(Db);
  const call = async (key: string, method: string, path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, headers: { 'x-api-key': key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json(); if (!r.ok) throw new Error(`${method} ${path} → ${r.status} ${JSON.stringify(j)}`); return j as any;
  };

  say('1. Register asset context and ingest a SARIF report + a secret-scanner webhook');
  await call('dev-analyst', 'POST', '/api/v1/assets', { name: 'payments', internetFacing: true, handlesCriticalData: true, environment: 'prod' });
  show(await call('dev-analyst', 'POST', '/api/v1/scans/ingest', { format: 'sarif', source: 'codeql', report: { runs: [{ tool: { driver: { name: 'codeql' } }, results: [
    { ruleId: 'js/sql-injection', level: 'error', message: { text: 'SQL injection' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'payments/db.js' }, region: { startLine: 42 } } }] },
    { ruleId: 'js/sql-injection', level: 'error', message: { text: 'SQL injection' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'tests/fixtures/db.js' } } }] }] }] } }));
  show(await call('dev-analyst', 'POST', '/api/v1/scans/ingest', { format: 'secrets', source: 'gitleaks', report: { findings: [{ rule: 'aws-access-key', secret: 'AKIAIOSFODNN7EXAMPLE', file: 'src/config.js', line: 3, repo: 'payments', verified: true }] } }));
  show((await call('dev-viewer', 'GET', '/api/v1/exposures/summary')).totals);

  say('2. Rotate the leaked credential (zero-downtime: new key is health-checked BEFORE the old one is touched)');
  const cred = db.credentials.list('org_acme')[0]; secrets.seed(cred.id);
  const rot = await call('dev-analyst', 'POST', '/api/v1/secrets/rotate', { credentialId: cred.id });
  await queue.idle();
  show((await call('dev-viewer', 'GET', `/api/v1/executions/${rot.executionId}`)).steps.map((s: any) => `${s.name}: ${s.status}`));
  console.log(`   active=v${await secrets.getActive(cred.id)}, old v1 still valid: ${await secrets.isValid(cred.id, 1)}  ← paused awaiting SecOps`);

  say('3. Brute-force alert from the API gateway → forensics frozen, isolation planned (NOT applied)');
  const inc = await call('dev-analyst', 'POST', '/api/v1/incidents/trigger', { kind: 'brute_force', source: '203.0.113.9', target: 'auth-api', count: 900, windowSec: 60, gatewayLogs: ['401 POST /login 203.0.113.9', '401 POST /login 203.0.113.9 password=hunter2hunter2'] });
  await queue.idle();
  const f = await call('dev-viewer', 'GET', `/api/v1/executions/${inc.executionId}/forensics`);
  console.log(f.incident.summary.split('\n').map((l: string) => '   ' + l).join('\n'));
  console.log(`   infra changes so far: ${infra.applied.length}`);

  say('4. SecOps inbox');
  const inbox = await call('dev-approver', 'GET', '/api/v1/approvals?status=pending');
  for (const a of inbox) { console.log(`   [${a.id}] ${a.plan.kind} → ${a.plan.targetRef}\n${a.plan.diff.split('\n').map((l: string) => '        ' + l).join('\n')}`); }

  say(`5. Approver ${reject ? 'REJECTS' : 'APPROVES'} every pending action`);
  for (const a of inbox) await call('dev-approver', 'POST', `/api/v1/approvals/${a.id}/decision`, { decision: reject ? 'rejected' : 'approved', comment: 'simulation' });
  await queue.idle();

  say('6. Outcome');
  console.log(`   old credential v1 valid: ${await secrets.isValid(cred.id, 1)}   infra changes: ${JSON.stringify(infra.applied)}`);
  const audit = await call('dev-viewer', 'GET', '/api/v1/audit');
  console.log(`   audit entries: ${audit.entries.length}, hash-chain intact: ${audit.verify.ok}`);
  await app.close();
})().catch((e) => { console.error(e); process.exit(1); });
