import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { boot, Env } from './helpers';
import { NotificationsService, Mailer } from '../src/notifications/notifications.service';

let t: Env, slack: Server, hooks: Array<{ url: string; body: any }>, reply: { status: number; body: string }, base: string, sent: Array<{ to: string[]; subject: string; text: string }>, mail: { mode: 'ok' | 'fail' | 'none' };
const mailer: Mailer = { async send(m) { if (mail.mode === 'fail') throw new Error('554 relay denied'); sent.push(m); return mail.mode === 'none' ? { accepted: [], response: '250 but nobody' } : { accepted: m.to, response: '250 queued' }; } };
beforeAll(() => { process.env.NOTIFY_ALLOW_HTTP = '1'; process.env.NOTIFY_PRIVATE_HOSTS = '["127.0.0.1"]'; process.env.NOTIFY_STORM_LIMIT = '3'; });
beforeEach(async () => {
  hooks = []; sent = []; reply = { status: 200, body: 'ok' }; mail = { mode: 'ok' };
  slack = createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { hooks.push({ url: req.url!, body: JSON.parse(b || '{}') }); res.writeHead(reply.status); res.end(reply.body); }); });
  await new Promise<void>((r) => slack.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${(slack.address() as AddressInfo).port}`;
  t = await boot({ mailer });
});
afterEach(async () => { await new Promise((r) => slack.close(r)); await t.queue.idle(); await t.app.close(); });
const svc = () => t.app.get(NotificationsService);
const adm = () => t.as('admin-key');
const chan = async (o: object = {}) => (await adm().post('/api/v1/notifications/channels', { kind: 'slack', name: 'soc', webhookUrl: `${base}/slack/T1/B1/secrettoken123`, minSeverity: 'medium', ...o }).expect(201)).body;
const notice = (o: object = {}) => ({ event: 'case.opened', severity: 'high' as const, subject: 'Host compromised', body: 'details', dedupKey: `k-${Math.random()}`, ...o });

describe('notifications', () => {
  it('stores the webhook sealed, never returns or audits it, and only reports "delivered" when the provider confirmed', async () => {
    const c = await chan(); expect(c).toMatchObject({ hasWebhook: true }); expect(JSON.stringify(c)).not.toContain('secrettoken123');
    expect(JSON.stringify(await t.db.channels.list('org_acme'))).not.toContain('secrettoken123'); expect(JSON.stringify(await t.audit.list('org_acme'))).not.toContain('secrettoken123');
    expect((await adm().post(`/api/v1/notifications/channels/${c.id}/test`).expect(200)).body).toMatchObject({ status: 'delivered', attempts: 1 }); expect(hooks[0].body.text).toMatch(/test notification/);
    reply = { status: 200, body: 'invalid_token' };                                               // HTTP 200 but Slack did not say "ok"
    expect((await adm().post(`/api/v1/notifications/channels/${c.id}/test`).expect(200)).body).toMatchObject({ status: 'failed', error: expect.stringMatching(/did not confirm/) });
    reply = { status: 500, body: 'boom' }; hooks.length = 0;
    const f = (await adm().post(`/api/v1/notifications/channels/${c.id}/test`).expect(200)).body; expect(f).toMatchObject({ status: 'failed', attempts: 2 }); expect(hooks).toHaveLength(2);   // one retry, then failure is recorded
    expect((await adm().get('/api/v1/notifications/log?status=failed')).body).toHaveLength(2);
  });
  it('filters by severity and event, dedupes inside the window and stops alert storms', async () => {
    await chan({ events: ['case.opened'], minSeverity: 'high' });
    expect(await svc().dispatch('org_acme', notice({ severity: 'low' }))).toHaveLength(0); expect(await svc().dispatch('org_acme', notice({ event: 'other' }))).toHaveLength(0);
    const k = notice(); expect((await svc().dispatch('org_acme', k))[0].status).toBe('delivered');
    expect((await svc().dispatch('org_acme', k))[0]).toMatchObject({ status: 'suppressed', reason: expect.stringMatching(/duplicate/) });
    await svc().dispatch('org_acme', notice()); await svc().dispatch('org_acme', notice());
    const storm = (await svc().dispatch('org_acme', notice()))[0]; expect(storm).toMatchObject({ status: 'suppressed', reason: expect.stringMatching(/storm/) }); expect(hooks).toHaveLength(3);
  });
  it('muting silences a channel; escalation reaches another channel when the first fails', async () => {
    const a = await chan({ name: 'primary' }), b = await adm().post('/api/v1/notifications/channels', { kind: 'teams', name: 'backup', webhookUrl: `${base}/teams/x`, minSeverity: 'critical' }).expect(201);
    await adm().post(`/api/v1/notifications/channels/${a.id}`, { mutedUntil: new Date(Date.now() + 3600_000).toISOString() }).expect(200);
    expect((await svc().dispatch('org_acme', notice()))[0]).toMatchObject({ status: 'suppressed', reason: expect.stringMatching(/muted/) });
    await adm().post(`/api/v1/notifications/channels/${a.id}`, { mutedUntil: null }).expect(200);
    const esc = await chan({ name: 'with-escalation', escalation: { afterSec: 0, channelId: b.body.id } }); reply = { status: 200, body: 'ok' };
    await adm().post(`/api/v1/notifications/channels/${a.id}`, { enabled: false }).expect(200);
    reply = { status: 500, body: 'down' }; hooks.length = 0;
    const out = await svc().dispatch('org_acme', notice({ severity: 'high', subject: 'Primary is down' }));
    expect(out.find((l) => l.channelId === esc.id)!.status).toBe('failed');
    const logs = (await adm().get('/api/v1/notifications/log')).body as any[]; expect(logs.some((l) => l.channelId === b.body.id && l.escalatedFrom === esc.id)).toBe(true);
    expect(hooks.some((h) => h.url.startsWith('/teams') && /ESCALATED/.test(h.body.title))).toBe(true);
  });
  it('email goes through the mail transport and counts as delivered only if the server accepted recipients', async () => {
    await adm().post('/api/v1/notifications/channels', { kind: 'email', name: 'mail', recipients: ['soc@acme.test'], minSeverity: 'info' }).expect(201);
    expect((await svc().dispatch('org_acme', notice()))[0].status).toBe('delivered'); expect(sent[0]).toMatchObject({ to: ['soc@acme.test'], subject: '[HIGH] Host compromised' });
    mail.mode = 'fail'; expect((await svc().dispatch('org_acme', notice()))[0]).toMatchObject({ status: 'failed', error: expect.stringMatching(/relay denied/) });
    mail.mode = 'none'; expect((await svc().dispatch('org_acme', notice()))[0]).toMatchObject({ status: 'failed', error: expect.stringMatching(/accepted no recipients/) });
    await adm().post('/api/v1/notifications/channels', { kind: 'email', name: 'x', recipients: [] }).expect(400);
  });
  it('redacts secrets in what leaves the platform, and refuses unsafe or off-provider webhooks', async () => {
    await chan(); await svc().dispatch('org_acme', notice({ body: 'leaked password=Sup3rS3cretValue and key AKIAIOSFODNN7EXAMPLE' }));
    expect(JSON.stringify(hooks[0].body)).not.toMatch(/Sup3rS3cretValue|AKIAIOSFODNN7EXAMPLE/);
    await adm().post('/api/v1/notifications/channels', { kind: 'slack', name: 'x', webhookUrl: 'http://169.254.169.254/latest' }).expect(400);
    await adm().post('/api/v1/notifications/channels', { kind: 'slack', name: 'x', webhookUrl: 'https://evil.example.org/hook' }).expect(400);
    await adm().post('/api/v1/notifications/channels', { kind: 'teams', name: 'x', webhookUrl: 'https://hooks.slack.com/services/a/b/c' }).expect(400);
  });
  it('requires channel permissions, is tenant isolated and plan gated', async () => {
    const c = await chan();
    await t.analyst.post('/api/v1/notifications/channels', { kind: 'slack', name: 'x', webhookUrl: `${base}/x` }).expect(403); await t.analyst.post(`/api/v1/notifications/channels/${c.id}/test`).expect(403);
    expect((await t.viewer.get('/api/v1/notifications/channels')).body).toHaveLength(1);
    await t.other.post(`/api/v1/notifications/channels/${c.id}`, { enabled: false }).expect(403); expect((await t.other.get('/api/v1/notifications/channels')).body).toEqual([]);
    expect((await svc().dispatch('org_other', notice())).length).toBe(0);
    await t.db.orgs.put({ id: 'org_acme', orgId: 'org_platform', name: 'a', plan: 'starter', status: 'active', retentionDays: 365, createdAt: '', createdBy: 'x' });
    await t.viewer.get('/api/v1/notifications/channels').expect(402);
  });
  it('SOAR notify steps use the channels and respect dedup per playbook+entity', async () => {
    await chan({ events: ['playbook.endpoint-compromised'] }); await t.analyst.post('/api/v1/soar/playbooks/install-defaults').expect(200);
    await t.analyst.post('/api/v1/inventory/assets', { type: 'endpoint', identifier: 'web-01' }).expect(201);
    await t.analyst.post('/api/v1/signals', { signals: [{ source: 'defender', sourceId: 'a1', title: 'Ransomware behaviour', severity: 'critical', host: 'web-01' }] }).expect(201);
    const run = (await t.viewer.get('/api/v1/soar/runs')).body[0]; expect(run.steps[1]).toMatchObject({ action: 'notify', status: 'executed', result: { channels: 1, delivered: 1 } });
    expect(hooks.some((h) => /High-severity detection on web-01/.test(h.body.text))).toBe(true);
  });
});
