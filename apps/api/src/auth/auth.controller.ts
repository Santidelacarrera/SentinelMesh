import { Body, Controller, ForbiddenException, Get, Headers, HttpCode, Param, Post, UseGuards } from '@nestjs/common';
import { z } from 'zod';
import { ClientIp, Me, MinRole, Perm, Principal, RolesGuard } from './auth';
import { AccountsService, CreateOrgSchema, CreateUserSchema, LoginSchema, RefreshSchema } from './accounts.service';
import { parse } from '../common/zod';
import { Entitlements } from '../platform/entitlements';
import { PLATFORM_ORG } from './rbac';
import { Db } from '../store/db';

const PwChange = z.object({ current: z.string().min(1).max(256), next: z.string().min(1).max(256) }).strict();
const Reset = z.object({ token: z.string().min(10).max(600), newPassword: z.string().min(1).max(256) }).strict();
const Code = z.object({ code: z.string().regex(/^\d{6}$/) }).strict();
const MfaOff = z.object({ password: z.string().min(1).max(256), code: z.string().regex(/^\d{6}$/) }).strict();
const RoleBody = z.object({ role: z.string().min(1).max(32), customRoles: z.array(z.string().max(64)).max(10).optional() }).strict();
const NewRole = z.object({ name: z.string().regex(/^[\w .-]{2,64}$/), permissions: z.array(z.string().max(64)).min(1).max(100) }).strict();
const OrgPatch = z.object({ plan: z.enum(['starter', 'business', 'enterprise']).optional(), status: z.enum(['active', 'suspended']).optional(), retentionDays: z.number().int().min(30).max(3650).optional() }).strict();

@Controller('api/v1')
export class AuthController {
  constructor(private acc: AccountsService, private ent: Entitlements, private db: Db) {}

  // ── public (credentials are in the body; throttled by the global limiter and by per-account lockout) ──
  @Post('auth/login') @HttpCode(200)
  login(@Body() b: unknown, @ClientIp() ip: string | undefined, @Headers('user-agent') ua?: string) { return this.acc.login(parse(LoginSchema, b), { ip, userAgent: ua }); }

  @Post('auth/refresh') @HttpCode(200)
  refresh(@Body() b: unknown, @ClientIp() ip: string | undefined, @Headers('user-agent') ua?: string) { return this.acc.refresh(parse(RefreshSchema, b).refreshToken, { ip, userAgent: ua }); }

  @Post('auth/password/reset') @HttpCode(204)
  async reset(@Body() b: unknown) { const r = parse(Reset, b); await this.acc.redeemReset(r.token, r.newPassword); }

  // ── any authenticated principal ──
  @Post('auth/logout') @HttpCode(204) @UseGuards(RolesGuard) @MinRole('viewer')
  async logout(@Me() me: Principal) { await this.acc.logout(me); }

  @Get('auth/sessions') @UseGuards(RolesGuard) @MinRole('viewer')
  sessions(@Me() me: Principal) { return this.acc.sessionsOf(me.orgId, me.userId); }

  @Post('auth/password') @HttpCode(204) @UseGuards(RolesGuard) @MinRole('viewer')
  async password(@Me() me: Principal, @Body() b: unknown) { const x = parse(PwChange, b); await this.acc.changePassword(me, x.current, x.next); }

  @Post('auth/mfa/begin') @UseGuards(RolesGuard) @MinRole('viewer')
  mfaBegin(@Me() me: Principal) { return this.acc.mfaBegin(me); }

  @Post('auth/mfa/confirm') @HttpCode(204) @UseGuards(RolesGuard) @MinRole('viewer')
  async mfaConfirm(@Me() me: Principal, @Body() b: unknown) { await this.acc.mfaConfirm(me, parse(Code, b).code); }

  @Post('auth/mfa/disable') @HttpCode(204) @UseGuards(RolesGuard) @MinRole('viewer')
  async mfaDisable(@Me() me: Principal, @Body() b: unknown) { const x = parse(MfaOff, b); await this.acc.mfaDisable(me, x.password, x.code); }

  @Get('plan') @UseGuards(RolesGuard) @MinRole('viewer')
  plan(@Me() me: Principal) { return this.ent.describe(me.orgId); }

  // ── organisation administration ──
  @Get('users') @UseGuards(RolesGuard) @Perm('users:manage')
  users(@Me() me: Principal) { return this.acc.listUsers(me.orgId); }

  @Post('users') @HttpCode(201) @UseGuards(RolesGuard) @Perm('users:manage')
  createUser(@Me() me: Principal, @Body() b: unknown) { return this.acc.createUser(me, me.orgId, parse(CreateUserSchema, b)); }

  @Post('users/:id/role') @HttpCode(200) @UseGuards(RolesGuard) @Perm('users:manage')
  role(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { const x = parse(RoleBody, b); return this.acc.setRole(me, id, x.role, x.customRoles); }

  @Post('users/:id/disable') @HttpCode(200) @UseGuards(RolesGuard) @Perm('users:manage')
  disable(@Me() me: Principal, @Param('id') id: string) { return this.acc.setStatus(me, id, 'disabled'); }

  @Post('users/:id/enable') @HttpCode(200) @UseGuards(RolesGuard) @Perm('users:manage')
  enable(@Me() me: Principal, @Param('id') id: string) { return this.acc.setStatus(me, id, 'active'); }

  @Post('users/:id/revoke-sessions') @HttpCode(204) @UseGuards(RolesGuard) @Perm('sessions:manage')
  async revoke(@Me() me: Principal, @Param('id') id: string) { await this.acc.adminRevoke(me, id); }

  @Post('users/:id/reset-token') @HttpCode(201) @UseGuards(RolesGuard) @Perm('users:manage')
  resetToken(@Me() me: Principal, @Param('id') id: string) { return this.acc.issueReset(me, id); }

  @Post('users/:id/mfa-reset') @HttpCode(204) @UseGuards(RolesGuard) @Perm('users:manage')
  async mfaReset(@Me() me: Principal, @Param('id') id: string) { await this.acc.mfaAdminReset(me, id); }

  @Get('roles') @UseGuards(RolesGuard) @Perm('roles:manage')
  roles(@Me() me: Principal) { return this.acc.listRoles(me.orgId); }

  @Post('roles') @HttpCode(201) @UseGuards(RolesGuard) @Perm('roles:manage')
  newRole(@Me() me: Principal, @Body() b: unknown) { const x = parse(NewRole, b); return this.acc.createRole(me, x.name, x.permissions); }

  // ── platform (central administration; only platform administrators of the platform organisation) ──
  @Get('platform/orgs') @UseGuards(RolesGuard) @Perm('platform:manage')
  orgs(@Me() me: Principal) { this.only(me); return this.acc.listOrgs(); }

  @Post('platform/orgs') @HttpCode(201) @UseGuards(RolesGuard) @Perm('platform:manage')
  createOrg(@Me() me: Principal, @Body() b: unknown) { this.only(me); return this.acc.createOrg(me, parse(CreateOrgSchema, b)); }

  @Post('platform/orgs/:id') @HttpCode(200) @UseGuards(RolesGuard) @Perm('platform:manage')
  patchOrg(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { this.only(me); return this.acc.updateOrg(me, id, parse(OrgPatch, b)); }

  private only(me: Principal) { if (me.orgId !== PLATFORM_ORG) throw new ForbiddenException('platform administration is only available in the platform organisation'); }
}
