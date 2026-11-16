import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { Identity, IdentityChange, IdentityRisk } from '../store/enterprise.models';
import type { Severity } from '../store/models';
import { AuditTrail } from '../audit/audit-trail';
import { Entitlements } from '../platform/entitlements';
import { AnalyticsClient } from '../analytics/analytics.client';
import { newId, now } from '../common/ids';
import { Principal } from '../auth/auth';

/** Entitlement names that grant (near-)unrestricted power across providers. Heuristic, listed so reviewers can challenge it. */
const PRIV = [/^\*$/, /^\*:\*$/, /^iam:\*$/i, /^sts:assumerole$/i, /administratoraccess/i, /^owner$/i, /global administrator/i, /privileged role administrator/i, /domain admins/i, /enterprise admins/i, /\bcluster-admin\b/i, /^roles\/(owner|editor)$/i, /^super ?admin$/i];
export const isPrivilegedEntitlement = (e: string) => PRIV.some((r) => r.test(e.trim()));

export const IdentitySchema = z.object({
  kind: z.enum(['human', 'service']), name: z.string().min(1).max(200), email: z.string().email().max(254).optional(), provider: z.string().min(1).max(60), externalId: z.string().min(1).max(300),
  privileged: z.boolean().optional(), status: z.enum(['active', 'disabled']).default('active'), mfaEnabled: z.boolean().optional(), lastActivityAt: z.string().datetime().optional(),
  credentialAgeDays: z.number().int().min(0).max(36500).optional(), entitlements: z.array(z.string().min(1).max(200)).max(5000).default([]), usedEntitlements: z.array(z.string().min(1).max(200)).max(5000).optional(),
  authMethods: z.array(z.string().max(60)).max(20).default([]), assetIds: z.array(z.string().max(100)).max(500).default([]),
}).strict();
export type IdentityInput = z.infer<typeof IdentitySchema>;

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

@Injectable()
export class IamService {
  constructor(private db: Db, private audit: AuditTrail, private ent: Entitlements, private analytics: AnalyticsClient) {}

  /** Idempotent by (provider, externalId). Every privilege/status/MFA change is written to the append-only change history. */
  async upsert(me: Pick<Principal, 'orgId' | 'userId'>, i: IdentityInput): Promise<{ identity: Identity; created: boolean; changes: number }> {
    const t = now(), ex = (await this.db.identities.where(me.orgId, { provider: i.provider, externalId: i.externalId }))[0];
    const privileged = i.privileged ?? i.entitlements.some(isPrivilegedEntitlement);
    if (!ex) {
      const idn: Identity = { id: newId('idn'), orgId: me.orgId, kind: i.kind, name: i.name, email: i.email, provider: i.provider, externalId: i.externalId, privileged, status: i.status, mfaEnabled: i.mfaEnabled, lastActivityAt: i.lastActivityAt,
        credentialAgeDays: i.credentialAgeDays, entitlements: [...new Set(i.entitlements)], usedEntitlements: i.usedEntitlements, authMethods: i.authMethods, createdAt: t, lastSeen: t, assetIds: i.assetIds };
      const { row, created } = await this.db.identities.createUnique(idn, { provider: i.provider, externalId: i.externalId });
      if (created) {
        await this.change(me.orgId, row.id, 'discovered', undefined, { privileged, entitlements: row.entitlements.length }, me.userId);
        await this.audit.append(me.orgId, me.userId, 'identity.discovered', { identityId: row.id, provider: i.provider, kind: i.kind, privileged });
        return { identity: row, created: true, changes: 1 };
      }
      return { identity: row, created: false, changes: 0 };
    }
    let changes = 0;
    const next = new Set(i.entitlements), prev = new Set(ex.entitlements);
    const added = [...next].filter((e) => !prev.has(e)), removed = [...prev].filter((e) => !next.has(e));
    if (added.length) { await this.change(me.orgId, ex.id, 'privilege_added', undefined, added, me.userId); changes++; }
    if (removed.length) { await this.change(me.orgId, ex.id, 'privilege_removed', removed, undefined, me.userId); changes++; }
    if (ex.status !== i.status) { await this.change(me.orgId, ex.id, 'status_changed', ex.status, i.status, me.userId); changes++; }
    if (i.mfaEnabled !== undefined && ex.mfaEnabled !== i.mfaEnabled) { await this.change(me.orgId, ex.id, 'mfa_changed', ex.mfaEnabled, i.mfaEnabled, me.userId); changes++; }
    const identity = await this.db.identities.update(me.orgId, ex.id, (r) => {
      Object.assign(r, { name: i.name, email: i.email ?? r.email, privileged, status: i.status, lastSeen: t, entitlements: [...next], authMethods: i.authMethods, assetIds: i.assetIds });
      if (i.mfaEnabled !== undefined) r.mfaEnabled = i.mfaEnabled; if (i.lastActivityAt) r.lastActivityAt = i.lastActivityAt;
      if (i.credentialAgeDays !== undefined) r.credentialAgeDays = i.credentialAgeDays; if (i.usedEntitlements) r.usedEntitlements = i.usedEntitlements;
    });
    if (changes) await this.audit.append(me.orgId, me.userId, 'identity.changed', { identityId: ex.id, added: added.slice(0, 50), removed: removed.slice(0, 50) });
    return { identity, created: false, changes };
  }
  private change(orgId: string, identityId: string, kind: IdentityChange['kind'], before: unknown, after: unknown, actor: string) {
    return this.db.identityChanges.put({ id: newId('chg'), orgId, identityId, at: now(), kind, before, after, actor });
  }

  async list(orgId: string, q: Record<string, string | undefined>) {
    const text = q.q?.toLowerCase(), risks = q.risk ? await this.risks(orgId) : [];
    const riskIds = new Set(risks.filter((r) => r.code === q.risk).map((r) => r.identityId));
    const all = (await this.db.identities.list(orgId, (i) => (!q.kind || i.kind === q.kind) && (!q.provider || i.provider === q.provider) && (!q.status || i.status === q.status) && (q.privileged === undefined || String(i.privileged) === q.privileged)
      && (!q.risk || riskIds.has(i.id)) && (!text || `${i.name} ${i.email ?? ''}`.toLowerCase().includes(text)))).sort((a, b) => Number(b.privileged) - Number(a.privileged) || a.name.localeCompare(b.name));
    const limit = Math.min(Number(q.limit ?? 50) || 50, 200), offset = Math.max(Number(q.offset ?? 0) || 0, 0);
    return { total: all.length, items: all.slice(offset, offset + limit) };
  }
  async detail(orgId: string, id: string) {
    const identity = await this.db.identities.get(orgId, id); if (!identity) throw new NotFoundException('identity not found');
    const [changes, relations, all] = await Promise.all([this.db.identityChanges.where(orgId, { identityId: id }), this.db.relations.list(orgId, (r) => r.from === id || r.to === id), this.risks(orgId)]);
    return { identity, risks: all.filter((r) => r.identityId === id), changes: changes.sort((a, b) => b.at.localeCompare(a.at)), relations };
  }
  async changes(orgId: string, identityId?: string) { return (await this.db.identityChanges.list(orgId, (c) => !identityId || c.identityId === identityId)).sort((a, b) => b.at.localeCompare(a.at)).slice(0, 500); }

  /** Rule-based, explainable findings. Missing data yields "unverified" findings, never silence-as-safe or invented facts. */
  async risks(orgId: string, inactiveDays = Number(process.env.IAM_INACTIVE_DAYS ?? 90)): Promise<IdentityRisk[]> {
    const [ids, rels] = await Promise.all([this.db.identities.list(orgId), this.db.relations.list(orgId, (r) => ['can_assume', 'admin_of', 'trusts'].includes(r.kind))]);
    const byId = new Map(ids.map((i) => [i.id, i])), out: IdentityRisk[] = [], cut = Date.now() - inactiveDays * 86400000;
    for (const i of ids.filter((x) => x.status === 'active')) {
      const add = (code: IdentityRisk['code'], severity: Severity, detail: string, confidence: IdentityRisk['confidence'] = 'confirmed') => out.push({ identityId: i.id, code, severity, detail, confidence });
      if (i.privileged) add('privileged', i.kind === 'service' ? 'medium' : 'info', `holds privileged entitlements: ${i.entitlements.filter(isPrivilegedEntitlement).slice(0, 3).join(', ') || 'flagged by the source'}`);
      if (i.lastActivityAt) { if (Date.parse(i.lastActivityAt) < cut) add('inactive', i.privileged ? 'high' : 'medium', `no activity since ${i.lastActivityAt.slice(0, 10)} (> ${inactiveDays} days) but the account is still active`); }
      else add('inactive', 'low', 'no activity data from the source: cannot confirm whether the account is in use', 'unverified');
      if (i.usedEntitlements && i.entitlements.length >= 5) {
        const used = new Set(i.usedEntitlements), unused = i.entitlements.filter((e) => !used.has(e));
        if (unused.length / i.entitlements.length >= 0.7) add('excessive_permissions', i.privileged ? 'high' : 'medium', `${unused.length} of ${i.entitlements.length} entitlements unused in the observed period`);
      }
      if (i.kind === 'human' && i.privileged) { if (i.mfaEnabled === false) add('privileged_no_mfa', 'critical', 'privileged human account without MFA'); else if (i.mfaEnabled === undefined) add('privileged_no_mfa', 'medium', 'MFA status of a privileged account is unknown', 'unverified'); }
      if (i.kind === 'service' && (i.credentialAgeDays ?? 0) > 90) add('service_no_rotation', i.privileged ? 'high' : 'medium', `service credential is ${i.credentialAgeDays} days old (rotation policy: 90)`);
      const weak = i.authMethods.filter((m) => ['password', 'basic', 'ntlm', 'static_api_key', 'sms'].includes(m.toLowerCase()));
      if (weak.length && (i.privileged || i.kind === 'service')) add('weak_auth', i.privileged ? 'high' : 'medium', `relies on weak authentication: ${weak.join(', ')}`);
    }
    for (const r of rels) {
      const from = byId.get(r.from), to = byId.get(r.to);
      if (r.kind === 'can_assume' && from && to && to.privileged && !from.privileged && from.status === 'active')
        out.push({ identityId: from.id, code: 'dangerous_trust', severity: 'high', detail: `non-privileged identity can assume privileged identity "${to.name}" (privilege escalation path)`, confidence: r.confidence >= 0.8 ? 'confirmed' : 'suspected' });
    }
    return out.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  }
  async summary(orgId: string) {
    const [ids, risks] = await Promise.all([this.db.identities.list(orgId), this.risks(orgId)]);
    const real = risks.filter((r) => r.code !== 'privileged' && r.confidence !== 'unverified');
    return { total: ids.length, human: ids.filter((i) => i.kind === 'human').length, service: ids.filter((i) => i.kind === 'service').length, privileged: ids.filter((i) => i.privileged).length, disabled: ids.filter((i) => i.status === 'disabled').length,
      inactive: risks.filter((r) => r.code === 'inactive' && r.confidence === 'confirmed').length, risksBySeverity: Object.fromEntries((['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => [s, real.filter((r) => r.severity === s).length])), unverified: risks.filter((r) => r.confidence === 'unverified').length };
  }

  /**
   * Prepares (never applies) a least-privilege reduction. Applying it to a real provider is a destructive change that must go through
   * a SOAR run in ASSISTED mode with human approval; this method only computes the proposal from the evidence on record.
   */
  async proposeReduction(me: Principal, id: string) {
    const i = await this.db.identities.get(me.orgId, id); if (!i) throw new NotFoundException('identity not found');
    if (!i.usedEntitlements) throw new BadRequestException('no usage data recorded for this identity: a reduction cannot be proposed from guesses');
    const lp = await this.analytics.leastPrivilege(i.entitlements, i.usedEntitlements, ['*']);
    await this.audit.append(me.orgId, me.userId, 'identity.reduction_proposed', { identityId: id, unused: lp.unused.length });
    return { identityId: id, applied: false, note: 'proposal only: nothing was changed at the provider', keep: lp.used, remove: lp.unused, usageRatio: lp.usageRatio, proposedPolicy: lp.proposedPolicy };
  }
}
