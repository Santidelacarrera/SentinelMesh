import { boot, Env } from './helpers';
import { isPrivilegedEntitlement } from '../src/iam/iam.service';

let t: Env;
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });
const old = new Date(Date.now() - 200 * 86400000).toISOString(), recent = new Date(Date.now() - 2 * 86400000).toISOString();
const idn = (o: object = {}) => ({ kind: 'human', name: 'Ana', email: 'ana@acme.test', provider: 'entra', externalId: 'e-1', entitlements: ['Reader'], authMethods: ['mfa'], ...o });

describe('IAM', () => {
  it('detects privileged entitlements across providers', () => {
    for (const e of ['*', 'iam:*', 'AdministratorAccess', 'Global Administrator', 'Domain Admins', 'roles/owner']) expect(isPrivilegedEntitlement(e)).toBe(true);
    for (const e of ['s3:GetObject', 'Reader', 'roles/viewer']) expect(isPrivilegedEntitlement(e)).toBe(false);
  });
  it('registers identities idempotently and keeps a privilege change history', async () => {
    const a = (await t.analyst.post('/api/v1/iam/identities', idn({ lastActivityAt: recent })).expect(201)).body;
    expect(a.privileged).toBe(false);
    const again = (await t.analyst.post('/api/v1/iam/identities', idn({ lastActivityAt: recent })).expect(201)).body;
    expect(again.id).toBe(a.id);
    await t.analyst.post('/api/v1/iam/identities', idn({ entitlements: ['Reader', 'Global Administrator'], mfaEnabled: false, lastActivityAt: recent })).expect(201);
    const d = (await t.viewer.get(`/api/v1/iam/identities/${a.id}`).expect(200)).body;
    expect(d.identity.privileged).toBe(true);
    expect(d.changes.map((c: any) => c.kind)).toEqual(expect.arrayContaining(['discovered', 'privilege_added', 'mfa_changed']));
    expect(d.changes.find((c: any) => c.kind === 'privilege_added').after).toEqual(['Global Administrator']);
    await t.analyst.post('/api/v1/iam/identities', idn({ entitlements: ['Reader'], lastActivityAt: recent })).expect(201);
    expect((await t.viewer.get('/api/v1/iam/changes').expect(200)).body.some((c: any) => c.kind === 'privilege_removed')).toBe(true);
    expect((await t.audit.list('org_acme')).map((e) => e.event)).toEqual(expect.arrayContaining(['identity.discovered', 'identity.changed']));
  });
  it('flags inactive, MFA-less privileged, stale service keys, weak auth, excessive permissions and escalation trust', async () => {
    const human = (await t.analyst.post('/api/v1/iam/identities', idn({ name: 'Boss', externalId: 'b', entitlements: ['Global Administrator'], mfaEnabled: false, lastActivityAt: old })).expect(201)).body;
    const svc = (await t.analyst.post('/api/v1/iam/identities', { kind: 'service', name: 'ci-bot', provider: 'aws', externalId: 'ci', entitlements: ['s3:*', 'iam:*'], credentialAgeDays: 400, authMethods: ['static_api_key'], lastActivityAt: recent }).expect(201)).body;
    const ent = ['a:1', 'a:2', 'a:3', 'a:4', 'a:5', 'a:6', 'a:7', 'a:8', 'a:9', 'a:10'];
    const fat = (await t.analyst.post('/api/v1/iam/identities', idn({ name: 'Fat', externalId: 'f', entitlements: ent, usedEntitlements: ['a:1', 'a:2'], lastActivityAt: recent })).expect(201)).body;
    const junior = (await t.analyst.post('/api/v1/iam/identities', idn({ name: 'Junior', externalId: 'j', lastActivityAt: recent })).expect(201)).body;
    const unknown = (await t.analyst.post('/api/v1/iam/identities', idn({ name: 'NoData', externalId: 'n' })).expect(201)).body;
    await t.db.relations.put({ id: 'rel_x', orgId: 'org_acme', from: junior.id, to: svc.id, kind: 'can_assume', source: 'aws', confidence: 0.95, createdAt: '' });
    const risks = (await t.viewer.get('/api/v1/iam/risks').expect(200)).body as any[];
    const has = (id: string, code: string) => risks.find((r) => r.identityId === id && r.code === code);
    expect(has(human.id, 'inactive')).toMatchObject({ severity: 'high', confidence: 'confirmed' });
    expect(has(human.id, 'privileged_no_mfa')).toMatchObject({ severity: 'critical' });
    expect(has(svc.id, 'service_no_rotation')).toBeTruthy(); expect(has(svc.id, 'weak_auth')).toBeTruthy();
    expect(has(fat.id, 'excessive_permissions')).toBeTruthy();
    expect(has(junior.id, 'dangerous_trust')).toMatchObject({ severity: 'high', confidence: 'confirmed' });
    expect(has(unknown.id, 'inactive')).toMatchObject({ confidence: 'unverified' });     // no data ⇒ "cannot confirm", not "safe" and not "inactive"
    expect(risks[0].severity).toBe('critical');
    const s = (await t.viewer.get('/api/v1/iam/summary').expect(200)).body;
    expect(s).toMatchObject({ total: 5, privileged: 2, service: 1 }); expect(s.unverified).toBeGreaterThan(0);
    expect((await t.viewer.get('/api/v1/iam/identities?risk=privileged_no_mfa')).body.items.map((i: any) => i.id)).toEqual([human.id]);
  });
  it('proposes a least-privilege reduction only from real usage data, and never applies it', async () => {
    const a = (await t.analyst.post('/api/v1/iam/identities', idn({ entitlements: ['s3:Get', 's3:Put', 'iam:PassRole'], usedEntitlements: ['s3:Get'], lastActivityAt: recent })).expect(201)).body;
    const p = (await t.analyst.post(`/api/v1/iam/identities/${a.id}/propose-reduction`).expect(200)).body;
    expect(p).toMatchObject({ applied: false, keep: ['s3:Get'] }); expect(p.remove.sort()).toEqual(['iam:PassRole', 's3:Put']);
    const b = (await t.analyst.post('/api/v1/iam/identities', idn({ externalId: 'nodata' })).expect(201)).body;
    await t.analyst.post(`/api/v1/iam/identities/${b.id}/propose-reduction`).expect(400);
    expect((await t.viewer.get(`/api/v1/iam/identities/${a.id}`)).body.identity.entitlements).toHaveLength(3);          // untouched
  });
  it('validates input, enforces permissions and isolates tenants', async () => {
    const a = (await t.analyst.post('/api/v1/iam/identities', idn()).expect(201)).body;
    await t.analyst.post('/api/v1/iam/identities', { ...idn(), extra: 1 }).expect(400);
    await t.analyst.post('/api/v1/iam/identities', idn({ kind: 'robot' })).expect(400);
    await t.viewer.post('/api/v1/iam/identities', idn({ externalId: 'v' })).expect(403);
    await t.other.get(`/api/v1/iam/identities/${a.id}`).expect(404);
    expect((await t.other.get('/api/v1/iam/identities')).body.total).toBe(0);
    expect((await t.other.get('/api/v1/iam/risks')).body).toEqual([]);
    expect((await t.other.get('/api/v1/iam/changes')).body).toEqual([]);
    await t.db.orgs.put({ id: 'org_other', orgId: 'org_platform', name: 'o', plan: 'starter', status: 'active', retentionDays: 365, createdAt: '', createdBy: 'x' });
    await t.other.get('/api/v1/iam/identities').expect(402);                                                             // IAM is a business-plan feature
  });
});
