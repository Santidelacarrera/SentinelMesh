import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { UserAccount, Session, OrgProfile, Plan } from '../store/enterprise.models';
import { AuditTrail } from '../audit/audit-trail';
import { newId, now } from '../common/ids';
import { DUMMY_HASH, SecretBox, hashPassword, newTotpSecret, passwordProblems, randomToken, safeEqualHex, sha256hex, totpUri, verifyPassword, verifyTotp } from '../common/crypto';
import { Principal, encodeOrg } from './auth';
import { isRole, PLATFORM_ORG, ALL_PERMISSIONS } from './rbac';
import { Entitlements } from '../platform/entitlements';
import { Metrics } from '../ops/metrics';

export const SECRET_BOX = Symbol('SECRET_BOX');

const ACCESS_TTL_MS = () => Number(process.env.ACCESS_TOKEN_TTL_SEC ?? 900) * 1000;
const REFRESH_TTL_MS = () => Number(process.env.REFRESH_TOKEN_TTL_SEC ?? 7 * 86400) * 1000;
const MAX_SESSIONS = () => Number(process.env.MAX_CONCURRENT_SESSIONS ?? 5);
const MAX_FAILS = 5, LOCK_MS = () => Number(process.env.LOGIN_LOCK_SEC ?? 900) * 1000;
const iso = (ms: number) => new Date(ms).toISOString();

export const LoginSchema = z.object({ org: z.string().min(1).max(64), email: z.string().email().max(254), password: z.string().min(1).max(256), totp: z.string().regex(/^\d{6}$/).optional() }).strict();
export const RefreshSchema = z.object({ refreshToken: z.string().min(10).max(600) }).strict();
export const CreateUserSchema = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(256), role: z.string().default('viewer'), customRoles: z.array(z.string().max(64)).max(10).default([]) }).strict();
export const CreateOrgSchema = z.object({ id: z.string().regex(/^[a-z][a-z0-9_-]{2,40}$/), name: z.string().min(1).max(120), plan: z.enum(['starter', 'business', 'enterprise']).default('business'), adminEmail: z.string().email(), adminPassword: z.string().min(1).max(256) }).strict();

export interface Tokens { accessToken: string; refreshToken: string; expiresAt: string; refreshExpiresAt: string; sessionId: string }
const view = (u: UserAccount) => ({ id: u.id, email: u.email, role: u.role, customRoles: u.customRoles, status: u.status, mfaEnabled: !!u.mfa?.enabled, createdAt: u.createdAt, lastLoginAt: u.lastLoginAt, locked: !!u.lockedUntil && u.lockedUntil > now() });

@Injectable()
export class AccountsService implements OnModuleInit {
  constructor(private db: Db, private audit: AuditTrail, @Inject(SECRET_BOX) private box: SecretBox, private ent: Entitlements, private metrics: Metrics) {}

  /** Bootstraps the first platform administrator from the environment (secret from env, never logged). */
  async onModuleInit() {
    const email = process.env.PLATFORM_ADMIN_EMAIL, pw = process.env.PLATFORM_ADMIN_PASSWORD;
    if (!email || !pw) return;
    if ((await this.db.users.list(PLATFORM_ORG)).length) return;
    await this.createUser({ userId: 'system', orgId: PLATFORM_ORG, role: 'platform_admin', email: 'system' }, PLATFORM_ORG, { email, password: pw, role: 'platform_admin', customRoles: [] });
  }

  // ───────── users ─────────
  async createUser(by: Principal, orgId: string, i: z.infer<typeof CreateUserSchema>) {
    if (!isRole(i.role)) throw new BadRequestException('unknown role');
    if (i.role === 'platform_admin' && (orgId !== PLATFORM_ORG || by.role !== 'platform_admin')) throw new ForbiddenException('platform_admin can only be granted by a platform administrator inside the platform organisation');
    if (by.orgId !== orgId && by.role !== 'platform_admin') throw new ForbiddenException('cannot manage users of another organisation');
    const email = i.email.toLowerCase(), problems = passwordProblems(i.password, email);
    if (problems.length) throw new BadRequestException({ message: 'password rejected', problems });
    for (const n of i.customRoles) if (!(await this.db.roles.where(orgId, { name: n })).length) throw new BadRequestException(`unknown custom role ${n}`);
    if (i.customRoles.length) await this.ent.assertFeature(orgId, 'custom_roles');
    await this.ent.assertWithin(orgId, 'users', (await this.db.users.list(orgId)).length);
    const u: UserAccount = { id: newId('usr'), orgId, email, role: i.role, customRoles: i.customRoles, passwordHash: await hashPassword(i.password), passwordChangedAt: now(), failedLogins: 0, status: 'active', createdAt: now(), previousPasswordHashes: [] };
    const { row, created } = await this.db.users.createUnique(u, { email });
    if (!created) throw new ConflictException('a user with this email already exists');
    await this.audit.append(orgId, by.userId, 'user.created', { userId: row.id, email, role: row.role });
    return view(row);
  }
  async listUsers(orgId: string) { return (await this.db.users.list(orgId)).map(view); }
  private async user(orgId: string, id: string) { const u = await this.db.users.get(orgId, id); if (!u) throw new NotFoundException('user not found'); return u; }

  async setRole(by: Principal, id: string, role: string, customRoles?: string[]) {
    if (!isRole(role) || role === 'platform_admin') throw new BadRequestException('invalid role');
    const u = await this.user(by.orgId, id);
    if (u.id === by.userId) throw new ForbiddenException('separation of duties: you cannot change your own role');
    if (customRoles) for (const n of customRoles) if (!(await this.db.roles.where(by.orgId, { name: n })).length) throw new BadRequestException(`unknown custom role ${n}`);
    const out = await this.db.users.update(by.orgId, id, (r) => { r.role = role; if (customRoles) r.customRoles = customRoles; });
    await this.revokeUserSessions(by.orgId, id, 'role changed');
    await this.audit.append(by.orgId, by.userId, 'user.role_changed', { userId: id, from: u.role, to: role, customRoles: out.customRoles });
    return view(out);
  }
  async setStatus(by: Principal, id: string, status: 'active' | 'disabled') {
    if (id === by.userId) throw new ForbiddenException('you cannot disable your own account');
    await this.user(by.orgId, id);
    const out = await this.db.users.update(by.orgId, id, (r) => { r.status = status; if (status === 'active') { r.failedLogins = 0; delete r.lockedUntil; } });
    if (status === 'disabled') await this.revokeUserSessions(by.orgId, id, 'account disabled');
    await this.audit.append(by.orgId, by.userId, `user.${status === 'active' ? 'enabled' : 'disabled'}`, { userId: id });
    return view(out);
  }

  // ───────── login / sessions ─────────
  async login(i: z.infer<typeof LoginSchema>, ctx: { ip?: string; userAgent?: string }): Promise<Tokens> {
    const orgId = i.org, email = i.email.toLowerCase();
    const fail = async (reason: string, userId?: string): Promise<never> => { this.metrics.inc('sentinel_auth_failures_total', { reason: reason.replace(/[^a-z ]/gi, '').slice(0, 30) }, 1, 'failed login attempts'); await this.audit.append(orgId, userId ?? 'anonymous', 'auth.login_failed', { email, reason, ip: ctx.ip }); throw new UnauthorizedException('invalid credentials'); };
    const prof = await this.db.orgs.get(PLATFORM_ORG, orgId);
    const u = (await this.db.users.where(orgId, { email }))[0];
    const okPw = await verifyPassword(i.password, u?.passwordHash ?? DUMMY_HASH);          // same cost whether or not the account exists
    if (!u || prof?.status === 'suspended') return fail(u ? 'organisation suspended' : 'unknown account');
    if (u.status !== 'active') return fail('account disabled', u.id);
    if (u.lockedUntil && u.lockedUntil > now()) return fail('account locked', u.id);
    if (!okPw) {
      const n = (await this.db.users.update(orgId, u.id, (r) => { r.failedLogins++; if (r.failedLogins >= MAX_FAILS) { r.lockedUntil = iso(Date.now() + LOCK_MS()); r.failedLogins = 0; } })).lockedUntil;
      if (n && n > now()) await this.audit.append(orgId, u.id, 'auth.account_locked', { email, until: n, ip: ctx.ip });
      return fail('bad password', u.id);
    }
    if (u.mfa?.enabled) {
      const step = i.totp ? verifyTotp(this.box.decrypt(u.mfa.secretEnc, u.id), i.totp) : undefined;
      if (step === undefined) return fail(i.totp ? 'bad totp' : 'totp required', u.id);
      if (u.mfa.lastStep !== undefined && step <= u.mfa.lastStep) return fail('totp replay', u.id);            // a code works once
      await this.db.users.update(orgId, u.id, (r) => { r.mfa!.lastStep = step; });
    }
    await this.db.users.update(orgId, u.id, (r) => { r.failedLogins = 0; delete r.lockedUntil; r.lastLoginAt = now(); });
    const t = await this.issue(u, ctx);
    await this.audit.append(orgId, u.id, 'auth.login', { sessionId: t.sessionId, ip: ctx.ip, mfa: !!u.mfa?.enabled });
    return t;
  }

  private async issue(u: UserAccount, ctx: { ip?: string; userAgent?: string }, family = newId('fam')): Promise<Tokens> {
    const active = (await this.db.sessions.where(u.orgId, { userId: u.id })).filter((s) => !s.revokedAt && s.expiresAt > now()).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    for (const old of active.slice(0, Math.max(0, active.length - MAX_SESSIONS() + 1))) await this.revokeSession(u.orgId, old.id, 'concurrent session limit');
    const sid = newId('ses'), a = randomToken(), r = randomToken();
    const s: Session = { id: sid, orgId: u.orgId, userId: u.id, family, accessHash: sha256hex(a), refreshHash: sha256hex(r), usedRefreshHashes: [], expiresAt: iso(Date.now() + ACCESS_TTL_MS()), refreshExpiresAt: iso(Date.now() + REFRESH_TTL_MS()), createdAt: now(), lastSeenAt: now(), ip: ctx.ip, userAgent: ctx.userAgent?.slice(0, 200) };
    await this.db.sessions.put(s);
    const o = encodeOrg(u.orgId);
    return { accessToken: `smt.${o}.${sid}.${a}`, refreshToken: `smr.${o}.${sid}.${r}`, expiresAt: s.expiresAt, refreshExpiresAt: s.refreshExpiresAt, sessionId: sid };
  }

  /** Rotating refresh tokens. Presenting an already-used refresh token means theft or replay: the whole family is revoked. */
  async refresh(token: string, ctx: { ip?: string; userAgent?: string }): Promise<Tokens> {
    const [, o, sid, secret] = token.split('.');
    const bad = () => new UnauthorizedException('invalid refresh token');
    if (!o || !sid || !secret) throw bad();
    const orgId = Buffer.from(o, 'base64url').toString('utf8');
    const s = await this.db.sessions.get(orgId, sid); if (!s) throw bad();
    const h = sha256hex(secret);
    if (s.usedRefreshHashes.includes(h)) { await this.revokeFamily(orgId, s.family, 'refresh token reuse detected'); await this.audit.append(orgId, s.userId, 'auth.refresh_reuse_detected', { family: s.family, ip: ctx.ip }); throw bad(); }
    if (s.revokedAt || s.refreshExpiresAt <= now() || !safeEqualHex(h, s.refreshHash)) throw bad();
    const u = await this.db.users.get(orgId, s.userId); if (!u || u.status !== 'active') throw bad();
    await this.db.sessions.update(orgId, s.id, (r) => { r.revokedAt = now(); r.revokedReason = 'rotated'; r.usedRefreshHashes.push(h); });
    const t = await this.issue(u, ctx, s.family);
    await this.db.sessions.update(orgId, t.sessionId, (r) => { r.usedRefreshHashes = [...s.usedRefreshHashes, h]; });   // the new session inherits the burned tokens of its family
    return t;
  }

  async revokeSession(orgId: string, id: string, reason: string) { await this.db.sessions.update(orgId, id, (s) => { if (!s.revokedAt) { s.revokedAt = now(); s.revokedReason = reason; } }).catch(() => undefined); }
  async revokeFamily(orgId: string, family: string, reason: string) { for (const s of await this.db.sessions.where(orgId, { family })) await this.revokeSession(orgId, s.id, reason); }
  async revokeUserSessions(orgId: string, userId: string, reason: string) { for (const s of await this.db.sessions.where(orgId, { userId })) if (!s.revokedAt) await this.revokeSession(orgId, s.id, reason); }

  async logout(me: Principal) { if (me.sessionId) { await this.revokeSession(me.orgId, me.sessionId, 'logout'); await this.audit.append(me.orgId, me.userId, 'auth.logout', { sessionId: me.sessionId }); } }
  async sessionsOf(orgId: string, userId: string) { return (await this.db.sessions.where(orgId, { userId })).filter((s) => !s.revokedAt && s.expiresAt > now()).map((s) => ({ id: s.id, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, ip: s.ip, userAgent: s.userAgent, expiresAt: s.expiresAt })); }
  async adminRevoke(by: Principal, userId: string) { await this.user(by.orgId, userId); await this.revokeUserSessions(by.orgId, userId, 'revoked by administrator'); await this.audit.append(by.orgId, by.userId, 'sessions.revoked', { userId }); }

  // ───────── passwords ─────────
  private async setPassword(orgId: string, u: UserAccount, pw: string) {
    const problems = passwordProblems(pw, u.email); if (problems.length) throw new BadRequestException({ message: 'password rejected', problems });
    for (const old of [u.passwordHash, ...u.previousPasswordHashes]) if (await verifyPassword(pw, old)) throw new BadRequestException({ message: 'password rejected', problems: ['was used recently'] });
    const h = await hashPassword(pw);
    await this.db.users.update(orgId, u.id, (r) => { r.previousPasswordHashes = [r.passwordHash, ...r.previousPasswordHashes].slice(0, 5); r.passwordHash = h; r.passwordChangedAt = now(); r.failedLogins = 0; delete r.lockedUntil; });
  }
  async changePassword(me: Principal, current: string, next: string) {
    const u = await this.user(me.orgId, me.userId);
    if (!(await verifyPassword(current, u.passwordHash))) throw new UnauthorizedException('current password is wrong');
    await this.setPassword(me.orgId, u, next);
    for (const s of await this.db.sessions.where(me.orgId, { userId: u.id })) if (s.id !== me.sessionId) await this.revokeSession(me.orgId, s.id, 'password changed');
    await this.audit.append(me.orgId, me.userId, 'auth.password_changed', {});
  }
  /** Admin issues a one-time reset token (30 min). It is shown once; only its hash is stored. Delivery is out of band (see notifications). */
  async issueReset(by: Principal, userId: string) {
    await this.user(by.orgId, userId);
    const secret = randomToken(), id = newId('rst');
    await this.db.resets.put({ id, orgId: by.orgId, userId, tokenHash: sha256hex(secret), expiresAt: iso(Date.now() + 30 * 60_000), issuedBy: by.userId });
    await this.audit.append(by.orgId, by.userId, 'auth.reset_issued', { userId, resetId: id });
    return { token: `smp.${encodeOrg(by.orgId)}.${id}.${secret}`, expiresAt: iso(Date.now() + 30 * 60_000) };
  }
  async redeemReset(token: string, newPassword: string) {
    const [, o, id, secret] = token.split('.');
    const bad = () => new UnauthorizedException('invalid or expired reset token');
    if (!o || !id || !secret) throw bad();
    const orgId = Buffer.from(o, 'base64url').toString('utf8');
    const r = await this.db.resets.get(orgId, id);
    if (!r || r.usedAt || r.expiresAt <= now() || !safeEqualHex(sha256hex(secret), r.tokenHash)) throw bad();
    await this.db.resets.update(orgId, id, (x) => { if (x.usedAt) throw bad(); x.usedAt = now(); });     // single use, even under a race
    await this.setPassword(orgId, await this.user(orgId, r.userId), newPassword);
    await this.revokeUserSessions(orgId, r.userId, 'password reset');
    await this.audit.append(orgId, r.userId, 'auth.password_reset', { resetId: id });
  }

  // ───────── MFA ─────────
  async mfaBegin(me: Principal) {
    const u = await this.user(me.orgId, me.userId); if (u.mfa?.enabled) throw new ConflictException('MFA already enabled');
    const secret = newTotpSecret();
    await this.db.users.update(me.orgId, u.id, (r) => { r.mfa = { ...(r.mfa ?? { secretEnc: '', enabled: false }), pendingSecretEnc: this.box.encrypt(secret, u.id) }; });
    return { secret, otpauthUri: totpUri(secret, u.email) };
  }
  async mfaConfirm(me: Principal, code: string) {
    const u = await this.user(me.orgId, me.userId); const pend = u.mfa?.pendingSecretEnc;
    if (!pend) throw new BadRequestException('start MFA enrolment first');
    const step = verifyTotp(this.box.decrypt(pend, u.id), code); if (step === undefined) throw new BadRequestException('invalid code');
    await this.db.users.update(me.orgId, u.id, (r) => { r.mfa = { secretEnc: pend, enabled: true, lastStep: step }; });
    await this.audit.append(me.orgId, u.id, 'auth.mfa_enabled', {});
  }
  async mfaDisable(me: Principal, password: string, code: string) {
    const u = await this.user(me.orgId, me.userId);
    if (!u.mfa?.enabled || !(await verifyPassword(password, u.passwordHash)) || verifyTotp(this.box.decrypt(u.mfa.secretEnc, u.id), code) === undefined) throw new UnauthorizedException('invalid credentials');
    await this.db.users.update(me.orgId, u.id, (r) => { delete r.mfa; });
    await this.audit.append(me.orgId, u.id, 'auth.mfa_disabled', {});
  }
  async mfaAdminReset(by: Principal, userId: string) {
    await this.user(by.orgId, userId);
    await this.db.users.update(by.orgId, userId, (r) => { delete r.mfa; });
    await this.revokeUserSessions(by.orgId, userId, 'MFA reset');
    await this.audit.append(by.orgId, by.userId, 'auth.mfa_reset_by_admin', { userId });
  }

  // ───────── custom roles ─────────
  async createRole(by: Principal, name: string, permissions: string[]) {
    await this.ent.assertFeature(by.orgId, 'custom_roles');
    const unknown = permissions.filter((p) => !ALL_PERMISSIONS.has(p) || p === 'platform:manage');
    if (unknown.length) throw new BadRequestException(`unknown permissions: ${unknown.join(', ')}`);
    const { row, created } = await this.db.roles.createUnique({ id: newId('rol'), orgId: by.orgId, name, permissions, createdAt: now() }, { name });
    if (!created) throw new ConflictException('role already exists');
    await this.audit.append(by.orgId, by.userId, 'role.created', { name, permissions });
    return row;
  }
  listRoles(orgId: string) { return this.db.roles.list(orgId); }

  // ───────── platform (multi-tenant administration) ─────────
  async createOrg(by: Principal, i: z.infer<typeof CreateOrgSchema>): Promise<OrgProfile> {
    if (i.id === PLATFORM_ORG) throw new BadRequestException('reserved organisation id');
    const prof: OrgProfile = { id: i.id, orgId: PLATFORM_ORG, name: i.name, plan: i.plan, status: 'active', retentionDays: 365, createdAt: now(), createdBy: by.userId };
    const { row, created } = await this.db.orgs.createUnique(prof, { id: i.id });
    if (!created) throw new ConflictException('organisation already exists');
    await this.createUser({ ...by, orgId: i.id }, i.id, { email: i.adminEmail, password: i.adminPassword, role: 'admin', customRoles: [] });
    await this.audit.append(PLATFORM_ORG, by.userId, 'platform.org_created', { orgId: i.id, plan: i.plan });
    await this.audit.append(i.id, by.userId, 'org.created', { plan: i.plan, name: i.name });
    return row;
  }
  listOrgs() { return this.db.orgs.list(PLATFORM_ORG); }
  async updateOrg(by: Principal, id: string, patch: { plan?: Plan; status?: 'active' | 'suspended'; retentionDays?: number }) {
    if (!(await this.db.orgs.get(PLATFORM_ORG, id))) throw new NotFoundException('organisation not found');
    const out = await this.db.orgs.update(PLATFORM_ORG, id, patch);
    if (patch.status === 'suspended') for (const s of await this.db.sessions.list(id)) await this.revokeSession(id, s.id, 'organisation suspended');
    await this.audit.append(PLATFORM_ORG, by.userId, 'platform.org_updated', { orgId: id, ...patch });
    await this.audit.append(id, by.userId, 'org.updated_by_platform', patch);
    return out;
  }
}
