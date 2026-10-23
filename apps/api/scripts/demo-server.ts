/**
 * Demo/dev server with a realistic seeded organisation (in-memory, simulated cloud ports) so the console has something to show.
 *   npm run demo -w apps/api          # API on :3000, then `npm run dev -w apps/web`
 * Keys: dev-viewer, dev-analyst, dev-approver (header x-api-key).
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { JOB_QUEUE, MemoryQueue } from '../src/queue/queue';
import { PORTS } from '../src/workflow/ports';
import { SimulatedSecrets } from '../src/workflow/simulated';
import { Db } from '../src/store/db';

// These scripts are self-contained, in-memory demos: ignore any Redis/Postgres/S3/AWS settings left in the shell.
for (const k of ['REDIS_URL', 'DATABASE_URL', 'OBJECT_STORE_BUCKET', 'OBJECT_STORE_DIR', 'INFRA_MODE', 'ANALYTICS_URL', 'OIDC_ISSUER', 'MESH_ENFORCE_TENANT']) delete process.env[k];
process.env.HEALTH_RETRY_MS = '0';
const ORG = 'org_acme';

(async () => {
  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'] });
  await app.listen(Number(process.env.PORT ?? 3000));
  const base = `http://127.0.0.1:${new URL(await app.getUrl().then((u) => u.replace('[::1]', '127.0.0.1'))).port}`;
  const q = app.get<MemoryQueue>(JOB_QUEUE), secrets = app.get<SimulatedSecrets>(PORTS.SECRETS), db = app.get(Db);
  const call = async (key: string, method: string, path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, headers: { 'x-api-key': key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const j: any = await r.json(); if (!r.ok) throw new Error(`${method} ${path}: ${JSON.stringify(j)}`); return j;
  };
  const A = (m: string, p: string, b?: unknown) => call('dev-analyst', m, p, b);

  for (const a of [
    { name: 'payments', internetFacing: true, behindGateway: false, handlesCriticalData: true, environment: 'prod' },
    { name: 'auth-api', internetFacing: true, behindGateway: true, handlesCriticalData: true, environment: 'prod' },
    { name: 'billing', internetFacing: false, behindGateway: true, handlesCriticalData: true, environment: 'prod' },
    { name: 'internal-tool', internetFacing: false, behindGateway: true, handlesCriticalData: false, environment: 'dev' },
  ]) await A('POST', '/api/v1/assets', a);

  const loc = (uri: string, line = 1) => [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line } } }];
  await A('POST', '/api/v1/scans/ingest', { format: 'sarif', source: 'codeql · payments@main', report: { runs: [{ tool: { driver: { name: 'codeql', rules: [{ id: 'js/sql-injection', properties: { 'security-severity': '9.1' } }] } }, results: [
    { ruleId: 'js/sql-injection', level: 'error', message: { text: 'Consulta SQL construida con entrada del usuario' }, locations: loc('payments/src/db/orders.js', 88) },
    { ruleId: 'js/sql-injection', level: 'error', message: { text: 'Consulta SQL construida con entrada del usuario' }, locations: loc('tests/fixtures/orders.js', 12) },
    { ruleId: 'js/path-injection', level: 'warning', message: { text: 'Ruta de archivo derivada de entrada del usuario' }, locations: loc('billing/src/export.js', 41) },
    { ruleId: 'js/insecure-randomness', level: 'note', message: { text: 'Aleatoriedad no criptográfica para un token' }, locations: loc('internal-tool/src/token.js', 7) }] }] } });
  await A('POST', '/api/v1/scans/ingest', { format: 'trivy', source: 'trivy · auth-api:1.8.2', report: { Results: [{ Target: 'auth-api', Vulnerabilities: [
    { VulnerabilityID: 'CVE-2024-45337', PkgName: 'golang.org/x/crypto', InstalledVersion: '0.28.0', FixedVersion: '0.31.0', Severity: 'CRITICAL', Title: 'Bypass de autorización en ssh.ServerConfig.PublicKeyCallback' },
    { VulnerabilityID: 'CVE-2024-24790', PkgName: 'stdlib', InstalledVersion: '1.21.3', FixedVersion: '1.21.11', Severity: 'HIGH', Title: 'Comportamiento inesperado en net/netip' }] }] } });
  await A('POST', '/api/v1/scans/ingest', { format: 'zap', source: 'zap · staging', report: { site: [{ '@name': 'payments', alerts: [{ pluginid: '10038', name: 'Falta la cabecera Content-Security-Policy', riskcode: 1, instances: [{ uri: 'https://payments.acme.test/checkout' }] }, { pluginid: '40012', name: 'XSS reflejado', riskcode: 3, instances: [{ uri: 'https://payments.acme.test/search?q=' }] }] }] } });
  await A('POST', '/api/v1/scans/ingest', { format: 'secrets', source: 'gitleaks · payments', report: { findings: [
    { rule: 'aws-access-key', secret: 'AKIAIOSFODNN7EXAMPLE', file: 'payments/config/prod.env', line: 4, repo: 'payments', verified: true },
    { rule: 'billing-api-token', secret: 'demo-billing-refund-token-8f3a91c2d4e7', file: 'billing/scripts/refund.sh', line: 9, repo: 'billing', verified: true },
    { rule: 'generic-api-key', secret: 'YOUR_API_KEY_HERE', file: 'README.md', repo: 'payments' }] } });

  // History: one rotation already approved & completed, one rejected.
  const creds = (await db.credentials.list(ORG)); creds.forEach((c) => secrets.seed(c.id));
  const done = await A('POST', '/api/v1/secrets/rotate', { credentialId: creds[1].id }); await q.idle();
  const [h1] = (await db.approvals.list(ORG, (a) => a.executionId === done.executionId));
  await call('dev-approver', 'POST', `/api/v1/approvals/${h1.id}/decision`, { decision: 'approved', comment: 'Servicio verificado con la nueva clave; revocar la anterior.' }); await q.idle();

  // Waiting for a human:
  await A('POST', '/api/v1/secrets/rotate', { credentialId: creds[0].id });
  const sqli = (await db.findings.list(ORG)).find((f) => f.ruleId === 'js/sql-injection' && f.status === 'open')!;
  await A('POST', '/api/v1/remediations/simulate', { findingId: sqli.id, kind: 'waf', targetRef: 'payments-gateway', submitForApproval: true, params: { rule: { name: 'block-sqli-offenders', action: 'block', priority: 10, addresses: ['203.0.113.0/24', '198.51.100.17/32'] } } });
  await A('POST', '/api/v1/iam/audit-roles', { roleName: 'billing-batch-role', critical: true, submitForApproval: true, resources: ['arn:aws:s3:::acme-billing/*'],
    grantedActions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 's3:PutBucketPolicy', 'iam:PassRole', 'sqs:*'],
    auditEvents: [...Array(240).fill('s3:GetObject'), ...Array(31).fill('s3:PutObject'), ...Array(12).fill('sqs:SendMessage')] });
  await A('POST', '/api/v1/incidents/trigger', { kind: 'brute_force', source: '203.0.113.9', target: 'auth-api', count: 1840, windowSec: 60, gatewayLogs: [
    '2026-10-10T19:41:02Z 401 POST /login ip=203.0.113.9 user=admin', '2026-10-10T19:41:02Z 401 POST /login ip=203.0.113.9 user=root',
    '2026-10-10T19:41:03Z 401 POST /login ip=203.0.113.9 user=ana.perez', '2026-10-10T19:41:03Z 429 POST /login ip=203.0.113.9 rate-limited'] });
  await q.idle();
  console.log(`SentinelMesh demo listo en http://localhost:${process.env.PORT ?? 3000}  (x-api-key: dev-viewer | dev-analyst | dev-approver)`);
})().catch((e) => { console.error(e); process.exit(1); });
