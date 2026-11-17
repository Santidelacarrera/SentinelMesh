import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { createTransport } from 'nodemailer';
import { Db } from '../store/db';
import { NotificationChannel, NotificationLog } from '../store/enterprise.models';
import type { Severity } from '../store/models';
import { AuditTrail } from '../audit/audit-trail';
import { SecretBox } from '../common/crypto';
import { SECRET_BOX } from '../auth/accounts.service';
import { assertSafeUrl } from '../common/ssrf';
import { redact, redactString } from '../common/mask';
import { newId, now, sha256 } from '../common/ids';
import { Principal } from '../auth/auth';
import { Metrics } from '../ops/metrics';

export const MAILER = Symbol('MAILER');
/** Resolves only when the mail server ACCEPTED the message (SMTP 2xx). */
export interface Mailer { send(m: { to: string[]; subject: string; text: string }): Promise<{ accepted: string[]; response: string }> }
export class SmtpMailer implements Mailer {
  async send(m: { to: string[]; subject: string; text: string }) {
    const url = process.env.SMTP_URL; if (!url) throw new Error('SMTP is not configured (set SMTP_URL)');
    const r = await createTransport(url).sendMail({ from: process.env.SMTP_FROM ?? 'sentinelmesh@localhost', to: m.to, subject: m.subject, text: m.text });
    return { accepted: r.accepted.map(String), response: String(r.response) };
  }
}

export const ChannelSchema = z.object({
  kind: z.enum(['email', 'slack', 'teams']), name: z.string().min(1).max(100), webhookUrl: z.string().url().max(1000).optional(), recipients: z.array(z.string().email()).max(50).default([]),
  minSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('high'), events: z.array(z.string().max(60)).max(50).default(['*']), groupWindowSec: z.number().int().min(0).max(86400).default(300),
  escalation: z.object({ afterSec: z.number().int().min(0).max(86400).default(0), channelId: z.string() }).strict().optional(),
}).strict().refine((c) => (c.kind === 'email' ? c.recipients.length > 0 : !!c.webhookUrl), 'email channels need recipients; slack/teams channels need a webhookUrl');
export interface Notice { event: string; severity: Severity; subject: string; body: string; dedupKey: string; link?: string }
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const STORM_LIMIT = () => Number(process.env.NOTIFY_STORM_LIMIT ?? 10);

@Injectable()
export class NotificationsService {
  constructor(private db: Db, private audit: AuditTrail, @Inject(SECRET_BOX) private box: SecretBox, @Inject(MAILER) private mailer: Mailer, private metrics: Metrics) {}

  private view(c: NotificationChannel) { const { targetEnc, ...r } = c; return { ...r, hasWebhook: !!targetEnc }; }
  private policy() { let priv: string[] = []; try { priv = JSON.parse(process.env.NOTIFY_PRIVATE_HOSTS ?? '[]'); } catch { /* none */ } return { allowHttp: process.env.NOTIFY_ALLOW_HTTP === '1', allowPrivateHosts: priv }; }

  async create(me: Principal, i: z.infer<typeof ChannelSchema>) {
    if (i.webhookUrl) {
      await assertSafeUrl(i.webhookUrl, this.policy()).catch((e) => { throw new BadRequestException(`webhook URL refused: ${(e as Error).message}`); });
      const host = new URL(i.webhookUrl).hostname;
      if (i.kind === 'slack' && !/(^|\.)slack\.com$/i.test(host) && !this.policy().allowPrivateHosts?.includes(host) && process.env.NOTIFY_ALLOW_ANY_HOST !== '1') throw new BadRequestException('Slack webhooks must be on slack.com');
      if (i.kind === 'teams' && !/(\.webhook\.office\.com|\.office\.com|\.logic\.azure\.com|\.powerplatform\.com)$/i.test(host) && !this.policy().allowPrivateHosts?.includes(host) && process.env.NOTIFY_ALLOW_ANY_HOST !== '1') throw new BadRequestException('Teams webhooks must be on office.com / logic.azure.com / powerplatform.com');
    }
    if (i.escalation && !(await this.db.channels.get(me.orgId, i.escalation.channelId))) throw new BadRequestException('escalation channel not found');
    const id = newId('chn');
    const c: NotificationChannel = { id, orgId: me.orgId, kind: i.kind, name: i.name, targetEnc: i.webhookUrl ? this.box.encrypt(i.webhookUrl, id) : undefined, recipients: i.recipients, minSeverity: i.minSeverity, events: i.events, groupWindowSec: i.groupWindowSec, escalation: i.escalation, enabled: true, createdAt: now() };
    await this.db.channels.put(c);
    await this.audit.append(me.orgId, me.userId, 'notification.channel_created', { channelId: id, kind: i.kind, name: i.name, minSeverity: i.minSeverity, events: i.events });   // never the webhook
    return this.view(c);
  }
  async list(orgId: string) { return (await this.db.channels.list(orgId)).map((c) => this.view(c)); }
  async patch(me: Principal, id: string, p: { enabled?: boolean; mutedUntil?: string | null; minSeverity?: Severity; events?: string[] }) {
    if (!(await this.db.channels.get(me.orgId, id))) throw new NotFoundException('channel not found');
    const out = await this.db.channels.update(me.orgId, id, (r) => { if (p.enabled !== undefined) r.enabled = p.enabled; if (p.mutedUntil !== undefined) r.mutedUntil = p.mutedUntil ?? undefined; if (p.minSeverity) r.minSeverity = p.minSeverity; if (p.events) r.events = p.events; });
    await this.audit.append(me.orgId, me.userId, 'notification.channel_updated', { channelId: id, ...p });
    return this.view(out);
  }
  async logs(orgId: string, q: { channelId?: string; status?: string }) { return (await this.db.notifications.list(orgId, (l) => (!q.channelId || l.channelId === q.channelId) && (!q.status || l.status === q.status))).sort((a, b) => b.at.localeCompare(a.at)).slice(0, 300); }

  /** Routes a notice to every matching channel. A notice counts as DELIVERED only after the provider confirmed it. */
  async dispatch(orgId: string, n: Notice): Promise<NotificationLog[]> {
    const out: NotificationLog[] = [];
    for (const c of await this.db.channels.list(orgId, (x) => x.enabled)) {
      if (RANK[n.severity] < RANK[c.minSeverity] || !(c.events.includes('*') || c.events.includes(n.event))) continue;
      out.push(await this.deliverTo(c, n));
    }
    return out;
  }
  async test(me: Principal, id: string) {
    const c = await this.db.channels.get(me.orgId, id); if (!c) throw new NotFoundException('channel not found');
    const l = await this.deliverTo(c, { event: 'test', severity: 'info', subject: 'SentinelMesh test notification', body: `Channel "${c.name}" test requested by ${me.userId}.`, dedupKey: `test:${id}:${Date.now()}` }, true);
    await this.audit.append(me.orgId, me.userId, 'notification.channel_tested', { channelId: id, status: l.status });
    return l;
  }

  private async record(c: NotificationChannel, n: Notice, status: NotificationLog['status'], extra: Partial<NotificationLog> = {}, attempts = 0): Promise<NotificationLog> {
    const l: NotificationLog = { id: newId('ntf'), orgId: c.orgId, channelId: c.id, event: n.event, dedupKey: n.dedupKey, status, subject: redactString(n.subject).slice(0, 200), at: now(), attempts, ...extra };
    this.metrics.inc('sentinel_notifications_total', { kind: c.kind, status }, 1, 'notifications by channel kind and outcome');
    await this.db.notifications.put(l); return l;
  }
  private async deliverTo(c: NotificationChannel, n: Notice, force = false, escalatedFrom?: string): Promise<NotificationLog> {
    const since = new Date(Date.now() - c.groupWindowSec * 1000).toISOString();
    const recent = (await this.db.notifications.where(c.orgId, { channelId: c.id })).filter((l) => l.at >= since);
    if (!force) {
      if (c.mutedUntil && c.mutedUntil > now()) return this.record(c, n, 'suppressed', { reason: `channel muted until ${c.mutedUntil}` });
      if (recent.some((l) => l.dedupKey === n.dedupKey && l.status === 'delivered')) return this.record(c, n, 'suppressed', { reason: 'duplicate within the grouping window' });
      if (recent.filter((l) => l.status === 'delivered').length >= STORM_LIMIT()) return this.record(c, n, 'suppressed', { reason: `alert storm control: more than ${STORM_LIMIT()} notifications in ${c.groupWindowSec}s` });
    }
    const suppressed = recent.filter((l) => l.status === 'suppressed' && l.reason?.startsWith('alert storm')).length;
    const text = redactString(`${n.body}${n.link ? `\n${n.link}` : ''}${suppressed ? `\n(+${suppressed} similar notifications were suppressed by storm control)` : ''}`);
    let attempts = 0, last = '';
    for (; attempts < 2; ) {
      attempts++;
      try { const r = await this.send(c, n, text); return this.record(c, n, 'delivered', { providerResponse: r.slice(0, 200), escalatedFrom }, attempts); }
      catch (e) { last = redactString((e as Error).message).slice(0, 300); }
    }
    const failed = await this.record(c, n, 'failed', { error: last, escalatedFrom }, attempts);
    if (c.escalation && !escalatedFrom) { const to = await this.db.channels.get(c.orgId, c.escalation.channelId); if (to?.enabled) await this.deliverTo(to, { ...n, subject: `[ESCALATED: ${c.name} failed] ${n.subject}` }, true, c.id); }
    return failed;
  }
  private async send(c: NotificationChannel, n: Notice, text: string): Promise<string> {
    const subject = redactString(n.subject);
    if (c.kind === 'email') { const r = await this.mailer.send({ to: c.recipients, subject: `[${n.severity.toUpperCase()}] ${subject}`, text }); if (!r.accepted.length) throw new Error('SMTP server accepted no recipients'); return `smtp accepted ${r.accepted.length}: ${r.response}`; }
    const url = this.box.decrypt(c.targetEnc!, c.id);
    await assertSafeUrl(url, this.policy());
    const body = c.kind === 'slack' ? { text: `*[${n.severity.toUpperCase()}] ${subject}*\n${text}` }
      : { '@type': 'MessageCard', '@context': 'http://schema.org/extensions', summary: subject, themeColor: ({ critical: 'B3122A', high: 'D9480F', medium: 'B8860B', low: '0A6F6A', info: '4D6072' } as const)[n.severity], title: `[${n.severity.toUpperCase()}] ${subject}`, text };
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(redact(body)), redirect: 'manual', signal: AbortSignal.timeout(10000) });
    const t = (await res.text()).slice(0, 200);
    if (res.status < 200 || res.status >= 300) throw new Error(`provider answered HTTP ${res.status}`);
    if (c.kind === 'slack' && t.trim() !== 'ok') throw new Error(`Slack did not confirm delivery (body: ${t.trim() || 'empty'})`);
    return `HTTP ${res.status} ${t.trim()}`.trim();
  }
  dedup(parts: string[]) { return sha256(parts.join('|')).slice(0, 32); }
}
