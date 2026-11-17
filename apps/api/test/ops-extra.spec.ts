import { boot, Env, PW } from './helpers';
import { JsonLogger } from '../src/common/json-logger';
import { SecretBox } from '../src/common/crypto';
import { PLAN_LIMITS } from '../src/platform/entitlements';
import { ConnectorsService } from '../src/connectors/connectors.service';
import { NotificationsService } from '../src/notifications/notifications.service';
import { PrivacyService } from '../src/privacy/privacy.service';
import { runWithCorrelation, correlationFor } from '../src/common/correlation';

let t: Env;
beforeEach(async () => { t = await boot(); });
afterEach(async () => { await t.queue.idle(); await t.app.close(); });

describe('structured logs', () => {
  it('writes one JSON object per line with the request id and redacted secrets', () => {
    const lines: string[] = []; const log = new JsonLogger((l) => lines.push(l));
    runWithCorrelation(correlationFor('req-12345678', 'org_acme'), () => { log.log('login ok password=Sup3rS3cretValue', 'Auth'); log.error('boom', 'at x (secret=abcdef123456)', 'Engine'); });
    const [a, b] = lines.map((l) => JSON.parse(l));
    expect(a).toMatchObject({ level: 'info', context: 'Auth', requestId: 'req-12345678', tenant: 'org_acme' }); expect(a.msg).not.toContain('Sup3rS3cretValue'); expect(b.level).toBe('error'); expect(b.stack).not.toContain('abcdef123456');
  });
});

describe('daily event quota (plan limit)', () => {
  it('rejects ingestion beyond the plan quota with 402 and counts only accepted events', async () => {
    const prev = PLAN_LIMITS.business.eventsPerDay; PLAN_LIMITS.business.eventsPerDay = 3;
    try {
      await t.db.orgs.put({ id: 'org_acme', orgId: 'org_platform', name: 'a', plan: 'business', status: 'active', retentionDays: 365, createdAt: '', createdBy: 'x' });
      const sig = (n: number) => ({ source: 's', sourceId: `q${n}`, title: 'x', severity: 'low' });
      await t.analyst.post('/api/v1/signals', { signals: [sig(1), sig(2), sig(3)] }).expect(201);
      await t.analyst.post('/api/v1/signals', { signals: [sig(1)] }).expect(402);                       // quota already used (duplicates were not counted, but the day is full)
      await t.analyst.post('/api/v1/signals', { signals: [sig(4)] }).expect(402);
    } finally { PLAN_LIMITS.business.eventsPerDay = prev; }
  });
});

describe('key rotation', () => {
  it('re-seals connector credentials and webhooks with the new key; the old key alone can no longer decrypt', async () => {
    const platform = { userId: 'p', orgId: 'org_platform', role: 'platform_admin' as const, email: '' };
    await t.acc.createOrg(platform, { id: 'org_k', name: 'k', plan: 'enterprise', adminEmail: 'a@k.test', adminPassword: PW });
    const tok = (await t.http.post('/api/v1/auth/login').send({ org: 'org_k', email: 'a@k.test', password: PW })).body.accessToken, H = (r: any) => r.set('Authorization', `Bearer ${tok}`);
    process.env.NOTIFY_ALLOW_HTTP = '1'; process.env.NOTIFY_PRIVATE_HOSTS = '["127.0.0.1"]';
    await H(t.http.post('/api/v1/connectors')).send({ kind: 'wazuh', name: 'W', baseUrl: 'https://w.example.test', credentials: { username: 'u', password: 'pw-secret-1' } }).expect(201);
    await H(t.http.post('/api/v1/notifications/channels')).send({ kind: 'slack', name: 's', webhookUrl: 'http://127.0.0.1:9/hook' }).expect(201);
    const oldBlob = (await t.db.connectors.list('org_k'))[0].credentialsEnc!;
    const oldKey = Buffer.alloc(32, 1), newKey = Buffer.alloc(32, 2), box = new SecretBox(newKey, [oldKey]);
    // simulate that the data was sealed with the OLD key, then the operator rotated
    const svc = t.app.get(ConnectorsService) as unknown as { box: SecretBox }, notif = t.app.get(NotificationsService) as unknown as { box: SecretBox };
    const was = svc.box; const plain = was.decrypt(oldBlob, (await t.db.connectors.list('org_k'))[0].id);
    const old = new SecretBox(oldKey); const id = (await t.db.connectors.list('org_k'))[0].id; await t.db.connectors.update('org_k', id, { credentialsEnc: old.encrypt(plain, id) });
    const ch = (await t.db.channels.list('org_k'))[0]; await t.db.channels.update('org_k', ch.id, { targetEnc: old.encrypt('http://127.0.0.1:9/hook', ch.id) });
    svc.box = box; notif.box = box;
    expect((await H(t.http.post('/api/v1/connectors/reencrypt')).expect(200)).body).toEqual({ connectors: 1, channels: 1 });
    expect((await H(t.http.post('/api/v1/connectors/reencrypt')).expect(200)).body).toEqual({ connectors: 0, channels: 0 });          // idempotent
    const now = (await t.db.connectors.list('org_k'))[0].credentialsEnc!;
    expect(box.decrypt(now, id)).toBe(plain); expect(() => old.decrypt(now, id)).toThrow(); expect(new SecretBox(newKey).decrypt(now, id)).toBe(plain);     // works with the new key alone
    expect((await t.audit.list('org_k')).some((e) => e.event === 'secrets.reencrypted')).toBe(true);
    await t.other.post('/api/v1/connectors/reencrypt').expect(403);
  });
});

describe('scheduled retention', () => {
  it('runAll applies the policy to every active organisation', async () => {
    const platform = { userId: 'p', orgId: 'org_platform', role: 'platform_admin' as const, email: '' };
    await t.acc.createOrg(platform, { id: 'org_r', name: 'r', plan: 'enterprise', adminEmail: 'a@r.test', adminPassword: PW });
    const old = new Date(Date.now() - 800 * 86400000).toISOString();
    await t.db.signals.put({ id: 'sig_old', orgId: 'org_r', source: 's', sourceId: 'o', dedupKey: 'o', kind: 'alert', title: 'old', severity: 'low', at: old, cves: [], domains: [], ips: [], createdAt: old } as never);
    expect(await t.app.get(PrivacyService).runAll()).toBeGreaterThanOrEqual(1);
    expect(await t.db.signals.list('org_r')).toHaveLength(0);
    expect((await t.audit.list('org_r')).some((e) => e.event === 'privacy.retention_applied' && e.actor === 'retention-job')).toBe(true);
  });
});
