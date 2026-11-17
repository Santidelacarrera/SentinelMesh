import { CanActivate, ExecutionContext, ForbiddenException, Injectable, SetMetadata, UnauthorizedException, createParamDecorator } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { createHash, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, JWTVerifyGetKey } from 'jose';
import { SecOpsRole } from '../store/models';
import { Db } from '../store/db';
import { Entitlements, Feature as FeatureName } from '../platform/entitlements';
import { permissionsFor, PLATFORM_ORG } from './rbac';
import { safeEqualHex, sha256hex } from '../common/crypto';
import { now } from '../common/ids';

export interface Principal { userId: string; orgId: string; role: SecOpsRole; email: string; customRoles?: string[]; sessionId?: string; via?: 'session' | 'oidc' | 'apikey' }
const RANK: Record<SecOpsRole, number> = { viewer: 0, analyst: 1, approver: 2, admin: 3, platform_admin: 4 };

export const MinRole = (r: SecOpsRole) => SetMetadata('minRole', r);
/** Fine-grained permission (see auth/rbac.ts). Takes precedence over the coarse role rank when both are present. */
export const Perm = (p: string) => SetMetadata('perm', p);
/** Plan feature gate (see platform/entitlements.ts). */
export const Feature = (f: FeatureName) => SetMetadata('feature', f);
export const Me = createParamDecorator((_: unknown, ctx: ExecutionContext): Principal => ctx.switchToHttp().getRequest().principal);
export const ClientIp = createParamDecorator((_: unknown, ctx: ExecutionContext): string | undefined => ctx.switchToHttp().getRequest().ip);

export interface OidcConfig { issuer: string; audience: string; jwks?: JWTVerifyGetKey; jwksUri?: string; orgClaim?: string; roleClaim?: string }
const ROLES: SecOpsRole[] = ['viewer', 'analyst', 'approver', 'admin'];   // an IdP can never mint platform_admin

/** Verifies OIDC access tokens (RS/ES/PS/EdDSA via JWKS). `alg: none` and HMAC tokens are rejected by construction. */
export class OidcVerifier {
  private jwks: JWTVerifyGetKey;
  constructor(private c: OidcConfig) {
    this.jwks = c.jwks ?? createRemoteJWKSet(new URL(c.jwksUri ?? `${c.issuer.replace(/\/$/, '')}/.well-known/jwks.json`));
  }
  async verify(token: string): Promise<Principal | undefined> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, { issuer: this.c.issuer, audience: this.c.audience, algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'PS256', 'EdDSA'], requiredClaims: ['sub', 'exp'] });
      const org = payload[this.c.orgClaim ?? 'sentinel_org'], role = payload[this.c.roleClaim ?? 'sentinel_role'];
      if (typeof org !== 'string' || !org || org === PLATFORM_ORG || !ROLES.includes(role as SecOpsRole)) return undefined; // no tenant, platform tenant or unknown role → no access
      return { userId: String(payload.sub), orgId: org, role: role as SecOpsRole, email: String(payload['email'] ?? '') };
    } catch { return undefined; }
  }
}

export const encodeOrg = (orgId: string) => Buffer.from(orgId).toString('base64url');
export const decodeOrg = (s: string) => { try { return Buffer.from(s, 'base64url').toString('utf8'); } catch { return ''; } };

@Injectable()
export class AuthService {
  oidc?: OidcVerifier;
  allowApiKeys = process.env.AUTH_ALLOW_API_KEYS !== '0';
  private keys = new Map<string, Principal>(); // sha256(apiKey) -> principal
  constructor(private db: Db) {
    if (process.env.OIDC_ISSUER) this.oidc = new OidcVerifier({ issuer: process.env.OIDC_ISSUER, audience: process.env.OIDC_AUDIENCE ?? 'sentinelmesh', jwksUri: process.env.OIDC_JWKS_URI, orgClaim: process.env.OIDC_ORG_CLAIM, roleClaim: process.env.OIDC_ROLE_CLAIM });
    const raw = process.env.SENTINEL_API_KEYS; // JSON: [{key, userId, orgId, role, email}]
    if (raw) for (const k of JSON.parse(raw)) this.register(k.key, k);
    else if (process.env.NODE_ENV !== 'production') {
      // Dev defaults — never enabled in production.
      this.register('dev-viewer', { userId: 'u_viewer', orgId: 'org_acme', role: 'viewer', email: 'viewer@acme.test' });
      this.register('dev-analyst', { userId: 'u_analyst', orgId: 'org_acme', role: 'analyst', email: 'analyst@acme.test' });
      this.register('dev-approver', { userId: 'u_approver', orgId: 'org_acme', role: 'approver', email: 'approver@acme.test' });
    }
  }
  register(key: string, p: Principal) { this.keys.set(AuthService.h(key), p); }

  async authenticate(headers: Record<string, string | string[] | undefined>): Promise<Principal | undefined> {
    const bearer = /^Bearer (.+)$/i.exec(String(headers['authorization'] ?? ''))?.[1];
    if (bearer?.startsWith('smt.')) return this.bySession(bearer);
    if (bearer && this.oidc) { const p = await this.oidc.verify(bearer); return p && { ...p, via: 'oidc' }; }
    if (!this.allowApiKeys) return undefined;
    return this.byApiKey(headers['x-api-key'] as string | undefined);
  }

  /** `smt.<org b64>.<session id>.<secret>`: the org in the token only locates the row; the principal's org always comes from the stored session. */
  async bySession(token: string): Promise<Principal | undefined> {
    const [, o, sid, secret] = token.split('.');
    if (!o || !sid || !secret) return undefined;
    const orgId = decodeOrg(o); if (!orgId) return undefined;
    const s = await this.db.sessions.get(orgId, sid);
    if (!s || s.revokedAt || s.expiresAt <= now() || !safeEqualHex(sha256hex(secret), s.accessHash)) return undefined;
    const u = await this.db.users.get(s.orgId, s.userId);
    if (!u || u.status !== 'active') return undefined;
    const prof = await this.db.orgs.get(PLATFORM_ORG, s.orgId);
    if (prof?.status === 'suspended') return undefined;
    if (Date.parse(now()) - Date.parse(s.lastSeenAt) > 60_000) await this.db.sessions.update(s.orgId, s.id, { lastSeenAt: now() }).catch(() => {});
    return { userId: u.id, orgId: u.orgId, role: u.role as SecOpsRole, email: u.email, customRoles: u.customRoles, sessionId: s.id, via: 'session' };
  }

  private byApiKey(key: string | undefined): Principal | undefined {
    if (!key) return undefined;
    const h = AuthService.h(key);
    for (const [k, p] of this.keys) if (timingSafeEqual(Buffer.from(k), Buffer.from(h))) return { ...p, via: 'apikey' };
    return undefined;
  }
  private static h(k: string) { return createHash('sha256').update(k).digest('hex'); }
}

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private auth: AuthService, private reflector: Reflector, private db: Db, private ent: Entitlements) {}
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const p = await this.auth.authenticate(req.headers);
    if (!p) throw new UnauthorizedException('invalid or missing credentials');
    const meta = <T>(k: string) => this.reflector.getAllAndOverride<T>(k, [ctx.getHandler(), ctx.getClass()]);
    const perm = meta<string>('perm'), min = meta<SecOpsRole>('minRole') ?? 'viewer';
    if (perm) {
      const custom = p.customRoles?.length ? (await Promise.all(p.customRoles.map((n) => this.db.roles.where(p.orgId, { name: n })))).flat() : [];
      if (!permissionsFor(p.role, custom).has(perm)) throw new ForbiddenException(`requires permission ${perm}`);
    } else if (RANK[p.role] < RANK[min]) throw new ForbiddenException(`requires role ${min}`);
    // Behind the mesh the gateway sets X-Tenant from the verified JWT. If it is present (or required) it must agree with who the credential says we are.
    const tenant = req.headers['x-tenant'];
    if (process.env.MESH_ENFORCE_TENANT === '1' && !tenant) throw new ForbiddenException('missing x-tenant (requests must come through the mesh gateway)');
    if (tenant && tenant !== p.orgId) throw new ForbiddenException('x-tenant does not match the authenticated organisation');
    const feature = meta<FeatureName>('feature');
    if (feature && p.orgId !== PLATFORM_ORG) await this.ent.assertFeature(p.orgId, feature);
    req.principal = p;
    return true;
  }
}
