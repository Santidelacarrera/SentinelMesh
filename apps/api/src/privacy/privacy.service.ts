import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { AuditTrail } from '../audit/audit-trail';
import { AccountsService } from '../auth/accounts.service';
import { newId, now, sha256 } from '../common/ids';
import { Principal } from '../auth/auth';

export const RetentionSchema = z.object({ signalsDays: z.number().int().min(7).max(3650).optional(), notificationsDays: z.number().int().min(7).max(3650).optional(), sessionsDays: z.number().int().min(1).max(365).optional(), connectorRunsDays: z.number().int().min(7).max(3650).optional() }).strict();
export const DEFAULT_RETENTION = { signalsDays: 365, notificationsDays: 180, sessionsDays: 30, connectorRunsDays: 90 };
const cutoff = (days: number) => new Date(Date.now() - days * 86400000).toISOString();

/**
 * Privacy tooling for GDPR-style obligations: configurable retention, a full export of the organisation's own data, authorised erasure of a user.
 * The audit trail, evidence and case records are NEVER purged by retention (they may be under legal hold); erasure anonymises personal identifiers
 * in the account record while the audit trail keeps the pseudonymous user id. This is tooling, not a compliance certification.
 */
@Injectable()
export class PrivacyService {
  constructor(private db: Db, private audit: AuditTrail, private acc: AccountsService) {}
  async retention(orgId: string) { const s = (await this.db.settings.where(orgId, { key: 'retention' }))[0]; return { ...DEFAULT_RETENTION, ...((s?.value as object) ?? {}) }; }
  async setRetention(me: Principal, p: z.infer<typeof RetentionSchema>) {
    const next = { ...(await this.retention(me.orgId)), ...p }, ex = (await this.db.settings.where(me.orgId, { key: 'retention' }))[0];
    if (ex) await this.db.settings.update(me.orgId, ex.id, { value: next, updatedAt: now(), updatedBy: me.userId }); else await this.db.settings.put({ id: newId('set'), orgId: me.orgId, key: 'retention', value: next, updatedAt: now(), updatedBy: me.userId });
    await this.audit.append(me.orgId, me.userId, 'privacy.retention_changed', next);
    return next;
  }
  /** Deletes expired transient data. Signals that back a case or correlation are kept (they are part of an investigation). */
  async applyRetention(me: Pick<Principal, 'orgId' | 'userId'>) {
    const r = await this.retention(me.orgId), out = { signals: 0, notifications: 0, sessions: 0, resets: 0, connectorRuns: 0 };
    const keep = new Set((await this.db.cases.list(me.orgId)).flatMap((c) => c.signalIds));
    for (const s of await this.db.signals.list(me.orgId, (x) => x.createdAt < cutoff(r.signalsDays) && !keep.has(x.id) && !x.correlationId)) if (await this.db.signals.remove(me.orgId, s.id)) out.signals++;
    for (const n of await this.db.notifications.list(me.orgId, (x) => x.at < cutoff(r.notificationsDays))) if (await this.db.notifications.remove(me.orgId, n.id)) out.notifications++;
    for (const s of await this.db.sessions.list(me.orgId, (x) => (x.revokedAt ?? x.refreshExpiresAt) < cutoff(r.sessionsDays) && (!!x.revokedAt || x.refreshExpiresAt < now()))) if (await this.db.sessions.remove(me.orgId, s.id)) out.sessions++;
    for (const p of await this.db.resets.list(me.orgId, (x) => x.expiresAt < cutoff(1))) if (await this.db.resets.remove(me.orgId, p.id)) out.resets++;
    for (const c of await this.db.connectorRuns.list(me.orgId, (x) => x.startedAt < cutoff(r.connectorRunsDays))) if (await this.db.connectorRuns.remove(me.orgId, c.id)) out.connectorRuns++;
    await this.audit.append(me.orgId, me.userId, 'privacy.retention_applied', { ...out, policy: r });
    return { removed: out, policy: r, preserved: ['audit trail', 'evidence', 'cases', 'signals linked to cases or correlations'] };
  }
  /** Everything stored for the organisation, minus secrets (password hashes, MFA seeds, session hashes, sealed credentials and webhooks). */
  async exportAll(me: Principal) {
    const d = this.db, o = me.orgId;
    const strip = <T extends object>(rows: T[], drop: string[]) => rows.map((r) => Object.fromEntries(Object.entries(r).filter(([k]) => !drop.includes(k))));
    const data = {
      users: strip(await d.users.list(o), ['passwordHash', 'previousPasswordHashes', 'mfa']), roles: await d.roles.list(o), assets: await d.inventory.list(o), relations: await d.relations.list(o), vulnerabilities: await d.vulns.list(o), exposures: await d.exposures.list(o), exposureHistory: await d.exposureEvents.list(o),
      identities: await d.identities.list(o), identityChanges: await d.identityChanges.list(o), signals: await d.signals.list(o), correlations: await d.correlations.list(o), cases: await d.cases.list(o), evidenceMetadata: strip(await d.evidence.list(o), ['objectKey']),
      playbooks: await d.playbooks.list(o), playbookRuns: await d.runs.list(o), tickets: await d.tickets.list(o), notificationChannels: strip(await d.channels.list(o), ['targetEnc']), notificationLog: await d.notifications.list(o), connectors: strip(await d.connectors.list(o), ['credentialsEnc']),
      reports: strip(await d.reports.list(o), ['objectKey']), settings: await d.settings.list(o), audit: await this.audit.list(o),
    };
    const body = { exportedAt: now(), exportedBy: me.userId, organisation: o, format: 'sentinelmesh-export/1', data, notice: 'Secrets (password hashes, MFA seeds, sealed credentials and webhook URLs) are excluded. Evidence content is exported through the evidence export, which keeps its chain of custody.' };
    await this.audit.append(o, me.userId, 'privacy.export', { sha256: sha256(JSON.stringify(body)), counts: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, (v as unknown[]).length])) });
    return body;
  }
  /** Two-step: the caller must type the exact confirmation string. Personal identifiers are removed; the pseudonymous id stays so audit history remains coherent. */
  async eraseUser(me: Principal, userId: string, confirm: string) {
    const u = await this.db.users.get(me.orgId, userId); if (!u) throw new NotFoundException('user not found');
    if (u.id === me.userId) throw new BadRequestException('you cannot erase your own account');
    if (u.status === 'active' && u.role === 'admin' && (await this.db.users.list(me.orgId)).filter((x) => x.role === 'admin' && x.status === 'active').length <= 1) throw new ConflictException('cannot erase the last active administrator');
    if (confirm !== `ERASE ${u.email}`) throw new BadRequestException(`confirmation must be exactly: ERASE ${u.email}`);
    await this.acc.revokeUserSessions(me.orgId, userId, 'account erased');
    await this.db.users.update(me.orgId, userId, (r) => { r.email = `erased-${r.id}@invalid.invalid`; r.status = 'disabled'; r.passwordHash = 'erased'; r.previousPasswordHashes = []; delete r.mfa; r.customRoles = []; });
    for (const i of await this.db.identities.where(me.orgId, { email: u.email })) await this.db.identities.update(me.orgId, i.id, (r) => { r.email = undefined; r.name = `erased-${r.id}`; });
    await this.audit.append(me.orgId, me.userId, 'privacy.user_erased', { userId, note: 'personal identifiers removed; pseudonymous id retained in the audit trail' });
    return { userId, erased: true };
  }
}
