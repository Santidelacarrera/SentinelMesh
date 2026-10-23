import { CanActivate, ExecutionContext, ForbiddenException, Injectable, SetMetadata, UnauthorizedException, createParamDecorator } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { createHash, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, JWTVerifyGetKey } from 'jose';
import { SecOpsRole } from '../store/models';

export interface Principal { userId: string; orgId: string; role: SecOpsRole; email: string }
const RANK: Record<SecOpsRole, number> = { viewer: 0, analyst: 1, approver: 2, admin: 3 };

export const MinRole = (r: SecOpsRole) => SetMetadata('minRole', r);
export const Me = createParamDecorator((_: unknown, ctx: ExecutionContext): Principal => ctx.switchToHttp().getRequest().principal);

export interface OidcConfig { issuer: string; audience: string; jwks?: JWTVerifyGetKey; jwksUri?: string; orgClaim?: string; roleClaim?: string }
const ROLES: SecOpsRole[] = ['viewer', 'analyst', 'approver', 'admin'];

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
      if (typeof org !== 'string' || !org || !ROLES.includes(role as SecOpsRole)) return undefined; // no tenant or unknown role → no access
      return { userId: String(payload.sub), orgId: org, role: role as SecOpsRole, email: String(payload['email'] ?? '') };
    } catch { return undefined; }
  }
}

@Injectable()
export class AuthService {
  oidc?: OidcVerifier;
  allowApiKeys = process.env.AUTH_ALLOW_API_KEYS !== '0';
  private keys = new Map<string, Principal>(); // sha256(apiKey) -> principal
  constructor() {
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
    if (bearer && this.oidc) return this.oidc.verify(bearer);
    if (!this.allowApiKeys) return undefined;
    return this.byApiKey(headers['x-api-key'] as string | undefined);
  }
  private byApiKey(key: string | undefined): Principal | undefined {
    if (!key) return undefined;
    const h = AuthService.h(key);
    for (const [k, p] of this.keys) if (timingSafeEqual(Buffer.from(k), Buffer.from(h))) return p;
    return undefined;
  }
  private static h(k: string) { return createHash('sha256').update(k).digest('hex'); }
}

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private auth: AuthService, private reflector: Reflector) {}
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const p = await this.auth.authenticate(req.headers);
    if (!p) throw new UnauthorizedException('invalid or missing credentials');
    const min = this.reflector.getAllAndOverride<SecOpsRole>('minRole', [ctx.getHandler(), ctx.getClass()]) ?? 'viewer';
    if (RANK[p.role] < RANK[min]) throw new ForbiddenException(`requires role ${min}`);
    // Behind the mesh the gateway sets X-Tenant from the verified JWT. If it is present (or required) it must agree with who the credential says we are.
    const tenant = req.headers['x-tenant'];
    if (process.env.MESH_ENFORCE_TENANT === '1' && !tenant) throw new ForbiddenException('missing x-tenant (requests must come through the mesh gateway)');
    if (tenant && tenant !== p.orgId) throw new ForbiddenException('x-tenant does not match the authenticated organisation');
    req.principal = p;
    return true;
  }
}
