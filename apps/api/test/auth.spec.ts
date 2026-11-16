import { boot, Env, PW } from './helpers';
import { PLATFORM_ORG } from '../src/auth/rbac';
import { totpAt } from '../src/common/crypto';

let t: Env;
const platform = { userId: 'u_plat', orgId: PLATFORM_ORG, role: 'platform_admin' as const, email: 'root@platform.test' };
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });

const login = (org: string, email: string, password = PW, totp?: string) => t.http.post('/api/v1/auth/login').send({ org, email, password, ...(totp ? { totp } : {}) });
const bearer = (tok: string) => ({ get: (p: string) => t.http.get(p).set('Authorization', `Bearer ${tok}`), post: (p: string, b?: object) => t.http.post(p).set('Authorization', `Bearer ${tok}`).send(b ?? {}) });
async function mkOrg(id: string, plan = 'enterprise') {
  await t.acc.createOrg(platform, { id, name: id, plan: plan as any, adminEmail: `admin@${id.replace(/_/g, '')}.test`, adminPassword: PW });
  const r = await login(id, `admin@${id.replace(/_/g, '')}.test`).expect(200); return { admin: bearer(r.body.accessToken), tokens: r.body };
}

describe('accounts, sessions and MFA', () => {
  it('creates an org with its admin, who can log in and use the API with a session token', async () => {
    const { admin } = await mkOrg('org_a');
    const me = await admin.get('/api/v1/me').expect(200);
    expect(me.body).toMatchObject({ orgId: 'org_a', role: 'admin', via: 'session' });
    await admin.get('/api/v1/exposures/summary').expect(200);
  });
  it('enforces the password policy and unique emails; never stores plain passwords', async () => {
    const { admin } = await mkOrg('org_a');
    const weak = await admin.post('/api/v1/users', { email: 'w@a.test', password: 'short', role: 'viewer' }).expect(400);
    expect(JSON.stringify(weak.body)).toContain('at least 12');
    await admin.post('/api/v1/users', { email: 'ok@a.test', password: PW, role: 'viewer' }).expect(201);
    await admin.post('/api/v1/users', { email: 'OK@a.test', password: PW, role: 'viewer' }).expect(409);
    const stored = JSON.stringify(await t.db.users.list('org_a'));
    expect(stored).not.toContain(PW); expect(stored).toContain('scrypt$');
  });
  it('locks the account after repeated failures and does not reveal whether it exists', async () => {
    await mkOrg('org_a');
    const unknown = await login('org_a', 'nobody@a.test').expect(401);
    for (let i = 0; i < 5; i++) await login('org_a', 'admin@orga.test', 'wrong-password-123').expect(401);
    const locked = await login('org_a', 'admin@orga.test').expect(401);          // correct password, but locked
    expect(locked.body.message).toBe(unknown.body.message);
    expect((await t.audit.list('org_a')).some((e) => e.event === 'auth.account_locked')).toBe(true);
  });
  it('MFA: enrol, require a code at login, reject replays and wrong codes', async () => {
    const { admin } = await mkOrg('org_a');
    const b = await admin.post('/api/v1/auth/mfa/begin').expect(201);
    const step = Math.floor(Date.now() / 30000);
    await admin.post('/api/v1/auth/mfa/confirm', { code: totpAt(b.body.secret, step) }).expect(204);        // enrolment consumes this step
    await login('org_a', 'admin@orga.test').expect(401);                                                    // a code is required
    await login('org_a', 'admin@orga.test', PW, '000000').expect(401);
    await login('org_a', 'admin@orga.test', PW, totpAt(b.body.secret, step)).expect(401);                   // same step as enrolment => replay
    await login('org_a', 'admin@orga.test', PW, totpAt(b.body.secret, step + 3)).expect(401);               // outside the +-1 window
    await login('org_a', 'admin@orga.test', PW, totpAt(b.body.secret, step + 1)).expect(200);               // next step: fine
    await login('org_a', 'admin@orga.test', PW, totpAt(b.body.secret, step + 1)).expect(401);               // a good code works only once
  });
  it('rotates refresh tokens and revokes the whole family when one is reused', async () => {
    const { tokens } = await mkOrg('org_a');
    const r1 = await t.http.post('/api/v1/auth/refresh').send({ refreshToken: tokens.refreshToken }).expect(200);
    await bearer(r1.body.accessToken).get('/api/v1/me').expect(200);
    await bearer(tokens.accessToken).get('/api/v1/me').expect(401);                  // old access token died with the rotation
    await t.http.post('/api/v1/auth/refresh').send({ refreshToken: tokens.refreshToken }).expect(401);   // replay of the old refresh token…
    await bearer(r1.body.accessToken).get('/api/v1/me').expect(401);                 // …kills the legitimate descendant too
    expect((await t.audit.list('org_a')).some((e) => e.event === 'auth.refresh_reuse_detected')).toBe(true);
  });
  it('logout, admin revocation and the concurrent-session limit', async () => {
    const { admin } = await mkOrg('org_a');
    await admin.post('/api/v1/users', { email: 'u@a.test', password: PW, role: 'analyst' }).expect(201);
    const u = await login('org_a', 'u@a.test').expect(200);
    await bearer(u.body.accessToken).post('/api/v1/auth/logout').expect(204);
    await bearer(u.body.accessToken).get('/api/v1/me').expect(401);
    const u2 = await login('org_a', 'u@a.test').expect(200);
    const id = (await admin.get('/api/v1/users').expect(200)).body.find((x: any) => x.email === 'u@a.test').id;
    await admin.post(`/api/v1/users/${id}/revoke-sessions`).expect(204);
    await bearer(u2.body.accessToken).get('/api/v1/me').expect(401);
    const toks: string[] = []; for (let i = 0; i < 7; i++) toks.push((await login('org_a', 'u@a.test').expect(200)).body.accessToken);
    const alive = await Promise.all(toks.map((k) => bearer(k).get('/api/v1/me').then((r) => r.status)));
    expect(alive.filter((s) => s === 200)).toHaveLength(5);
  });
  it('password change revokes the other sessions; reset tokens work once and expire the sessions', async () => {
    const { admin } = await mkOrg('org_a');
    await admin.post('/api/v1/users', { email: 'u@a.test', password: PW, role: 'viewer' }).expect(201);
    const a = await login('org_a', 'u@a.test').expect(200), b = await login('org_a', 'u@a.test').expect(200);
    await bearer(a.body.accessToken).post('/api/v1/auth/password', { current: PW, next: 'Another-Strong-Pass-7' }).expect(204);
    await bearer(b.body.accessToken).get('/api/v1/me').expect(401);
    await bearer(a.body.accessToken).get('/api/v1/me').expect(200);
    await bearer(a.body.accessToken).post('/api/v1/auth/password', { current: 'Another-Strong-Pass-7', next: PW }).expect(400);   // reuse of a previous password
    const id = (await admin.get('/api/v1/users')).body.find((x: any) => x.email === 'u@a.test').id;
    const rst = await admin.post(`/api/v1/users/${id}/reset-token`).expect(201);
    await t.http.post('/api/v1/auth/password/reset').send({ token: rst.body.token, newPassword: 'Fresh-Password-42-x' }).expect(204);
    await t.http.post('/api/v1/auth/password/reset').send({ token: rst.body.token, newPassword: 'Fresh-Password-43-x' }).expect(401);
    await bearer(a.body.accessToken).get('/api/v1/me').expect(401);
    await login('org_a', 'u@a.test', 'Fresh-Password-42-x').expect(200);
  });
});

describe('authorization and tenant isolation', () => {
  it('users of one org never see or act on another org (and a forged token org does nothing)', async () => {
    const a = await mkOrg('org_a'), b = await mkOrg('org_b');
    const idB = (await b.admin.get('/api/v1/users')).body[0].id;
    expect((await a.admin.get('/api/v1/users')).body.map((u: any) => u.email)).toEqual(['admin@orga.test']);
    await a.admin.post(`/api/v1/users/${idB}/disable`).expect(404);
    await a.admin.post(`/api/v1/users/${idB}/reset-token`).expect(404);
    const [, , sid, secret] = a.tokens.accessToken.split('.');
    const forged = `smt.${Buffer.from('org_b').toString('base64url')}.${sid}.${secret}`;
    await bearer(forged).get('/api/v1/me').expect(401);
  });
  it('only platform administrators manage organisations; platform_admin cannot be granted elsewhere', async () => {
    const { admin } = await mkOrg('org_a');
    await admin.get('/api/v1/platform/orgs').expect(403);
    await admin.post('/api/v1/platform/orgs', { id: 'org_x', name: 'x', adminEmail: 'a@x.test', adminPassword: PW }).expect(403);
    await admin.post('/api/v1/users', { email: 'p@a.test', password: PW, role: 'platform_admin' }).expect(403);
    await expect(t.acc.createUser(platform, 'org_a', { email: 'p@a.test', password: PW, role: 'platform_admin', customRoles: [] })).rejects.toThrow(/platform administrator/);
  });
  it('custom roles add only the listed permissions; roles cannot be self-changed; unknown permissions are refused', async () => {
    const { admin } = await mkOrg('org_a');
    await admin.post('/api/v1/roles', { name: 'asset-editor', permissions: ['assets:write'] }).expect(201);
    await admin.post('/api/v1/roles', { name: 'bad', permissions: ['platform:manage'] }).expect(400);
    await admin.post('/api/v1/users', { email: 'e@a.test', password: PW, role: 'viewer', customRoles: ['asset-editor'] }).expect(201);
    const tok = (await login('org_a', 'e@a.test').expect(200)).body.accessToken;
    await bearer(tok).post('/api/v1/assets', { name: 'x', internetFacing: false }).expect(403);      // legacy /assets still needs the analyst role
    await bearer(tok).get('/api/v1/users').expect(403);
    const meId = (await admin.get('/api/v1/me')).body.userId;
    await admin.post(`/api/v1/users/${meId}/role`, { role: 'viewer' }).expect(403);                  // separation of duties
  });
  it('suspending an organisation kills its sessions and blocks login; plan gates features and limits', async () => {
    const { admin, tokens } = await mkOrg('org_a', 'starter');
    const p = (await admin.get('/api/v1/plan').expect(200)).body;
    expect(p.plan).toBe('starter'); expect(p.features).not.toContain('soar');
    await admin.post('/api/v1/roles', { name: 'r1', permissions: ['assets:read'] }).expect(402);       // custom roles are an enterprise feature
    await t.acc.updateOrg(platform, 'org_a', { status: 'suspended' });
    await bearer(tokens.accessToken).get('/api/v1/me').expect(401);
    await login('org_a', 'admin@orga.test').expect(401);
    expect((await t.audit.list(PLATFORM_ORG)).map((e) => e.event)).toEqual(expect.arrayContaining(['platform.org_created', 'platform.org_updated']));
  });
  it('legacy API keys keep working and are not mistaken for sessions', async () => {
    await t.viewer.get('/api/v1/exposures/summary').expect(200);
    await t.http.get('/api/v1/me').set('Authorization', 'Bearer smt.bm9wZQ.x.y').expect(401);
  });
});
