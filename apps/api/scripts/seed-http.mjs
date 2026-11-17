// Seeds an organisation with sample data over HTTP (for manual UI checks against any running instance).
//   BASE=http://localhost:38080/api/v1 PLATFORM_EMAIL=... PLATFORM_PASSWORD=... node apps/api/scripts/seed-http.mjs
const B = process.env.BASE ?? 'http://localhost:3000/api/v1', PW = 'Seed-User-Pass-2026!x';
const req = async (tok, method, path, body) => { const r = await fetch(B + path, { method, headers: { 'content-type': 'application/json', ...(tok ? { authorization: `Bearer ${tok}` } : {}) }, body: body && JSON.stringify(body) }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(`${method} ${path} ${r.status} ${JSON.stringify(j)}`); return j; };
const login = async (org, email, password) => (await req(null, 'POST', '/auth/login', { org, email, password })).accessToken;
const plat = await login('org_platform', process.env.PLATFORM_EMAIL, process.env.PLATFORM_PASSWORD);
await req(plat, 'POST', '/platform/orgs', { id: 'org_ui', name: 'Org de demostración', plan: 'enterprise', adminEmail: 'admin@ui.test', adminPassword: PW }).catch((e) => console.log('org:', e.message.slice(0, 80)));
const a = await login('org_ui', 'admin@ui.test', PW);
const web = await req(a, 'POST', '/inventory/assets', { type: 'server', identifier: 'web-01', criticality: 'critical', internetFacing: true });
const db = await req(a, 'POST', '/inventory/assets', { type: 'database', identifier: 'ledger-db', criticality: 'critical' });
await req(a, 'POST', '/inventory/relations', { from: web.id, to: db.id, kind: 'depends_on', confidence: 0.9 });
await req(a, 'POST', '/intel/import', { kind: 'kev', payload: { vulnerabilities: [{ cveID: 'CVE-2099-0001', dueDate: '2099-01-01' }] } });
await req(a, 'POST', '/vulns', { assetId: web.id, cve: 'CVE-2099-0001', title: 'Remote code execution', severity: 'critical', confidence: 'confirmed', source: 'seed' });
await req(a, 'POST', '/iam/identities', { kind: 'human', name: 'Root Ann', provider: 'entra', externalId: 'ann', entitlements: ['Global Administrator'], mfaEnabled: false, lastActivityAt: new Date().toISOString() });
await req(a, 'POST', '/soar/playbooks/install-defaults');
await req(a, 'POST', '/signals', { signals: [{ source: 'crowdstrike', sourceId: 's1', kind: 'detection', title: 'Credential dumping', severity: 'critical', host: 'web-01' }, { source: 'wazuh', sourceId: 's2', title: 'sshd brute force', severity: 'high', host: 'web-01' }] });
await req(a, 'POST', '/connectors', { kind: 'wazuh', name: 'Wazuh (sin credenciales)', baseUrl: 'https://wazuh.example.test' });
await req(a, 'POST', '/reports', { kind: 'executive' });
console.log('seeded: login with org=org_ui email=admin@ui.test password=' + PW);
