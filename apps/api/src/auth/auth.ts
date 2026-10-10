import { CanActivate, ExecutionContext, ForbiddenException, Injectable, SetMetadata, UnauthorizedException, createParamDecorator } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { createHash, timingSafeEqual } from 'node:crypto';
import { SecOpsRole } from '../store/models';

export interface Principal { userId: string; orgId: string; role: SecOpsRole; email: string }
const RANK: Record<SecOpsRole, number> = { viewer: 0, analyst: 1, approver: 2, admin: 3 };

export const MinRole = (r: SecOpsRole) => SetMetadata('minRole', r);
export const Me = createParamDecorator((_: unknown, ctx: ExecutionContext): Principal => ctx.switchToHttp().getRequest().principal);

@Injectable()
export class AuthService {
  private keys = new Map<string, Principal>(); // sha256(apiKey) -> principal
  constructor() {
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
  authenticate(key: string | undefined): Principal | undefined {
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
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const p = this.auth.authenticate(req.headers['x-api-key'] as string | undefined);
    if (!p) throw new UnauthorizedException('invalid or missing x-api-key');
    const min = this.reflector.getAllAndOverride<SecOpsRole>('minRole', [ctx.getHandler(), ctx.getClass()]) ?? 'viewer';
    if (RANK[p.role] < RANK[min]) throw new ForbiddenException(`requires role ${min}`);
    req.principal = p;
    return true;
  }
}
