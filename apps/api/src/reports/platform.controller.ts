import { Body, Controller, Get, Header, HttpCode, Param, Post, Query, Res, StreamableFile, UseGuards } from '@nestjs/common';
import { z } from 'zod';
import { Feature, Me, Perm, Principal, RolesGuard } from '../auth/auth';
import { parse } from '../common/zod';
import { DashboardService } from '../dashboard/dashboard.service';
import { ReportSchema, ReportsService } from './reports.service';
import { AiService, ExplainKind } from '../ai/ai.service';
import { PrivacyService, RetentionSchema } from '../privacy/privacy.service';

const Explain = z.object({ kind: z.enum(['case', 'vulnerability', 'attack_path', 'correlation', 'identity', 'priorities']), id: z.string().max(400).optional(), external: z.boolean().default(false) }).strict();
const Consent = z.object({ enabled: z.boolean() }).strict();
const Erase = z.object({ userId: z.string().min(1).max(100), confirm: z.string().min(5).max(300) }).strict();

@Controller('api/v1')
@UseGuards(RolesGuard)
export class PlatformController {
  constructor(private dash: DashboardService, private reports: ReportsService, private ai: AiService, private privacy: PrivacyService) {}

  @Get('dashboard/executive') @Perm('dashboard:read') @Feature('dashboard')
  executive(@Me() me: Principal, @Query('days') days?: string) { return this.dash.executive(me.orgId, Math.min(Math.max(Number(days) || 30, 7), 180)); }

  // ── reports ──
  @Get('reports') @Perm('reports:read') @Feature('reports')
  list(@Me() me: Principal) { return this.reports.list(me.orgId); }

  @Post('reports') @HttpCode(201) @Perm('reports:generate') @Feature('reports')
  async generate(@Me() me: Principal, @Body() b: unknown) { const { objectKey: _k, ...r } = await this.reports.generate(me, parse(ReportSchema, b)); return r; }

  @Get('reports/:id/pdf') @Perm('reports:read') @Feature('reports') @Header('Content-Type', 'application/pdf')
  async pdf(@Me() me: Principal, @Param('id') id: string, @Res({ passthrough: true }) res: { setHeader(k: string, v: string): void }) {
    const f = await this.reports.download(me, id); res.setHeader('Content-Disposition', `attachment; filename="${f.name}"`); return new StreamableFile(f.bytes);
  }

  // ── AI assistant ──
  @Post('ai/explain') @HttpCode(200) @Perm('ai:use') @Feature('ai')
  explain(@Me() me: Principal, @Body() b: unknown) { const x = parse(Explain, b); return this.ai.explain(me, x.kind as ExplainKind, x.id, x.external); }

  @Get('ai/settings') @Perm('ai:use') @Feature('ai')
  aiSettings(@Me() me: Principal) { return this.ai.settings(me.orgId); }

  @Post('ai/settings') @HttpCode(200) @Perm('settings:manage') @Feature('ai')
  setAi(@Me() me: Principal, @Body() b: unknown) { return this.ai.setConsent(me, parse(Consent, b).enabled); }

  // ── privacy ──
  @Get('privacy/retention') @Perm('privacy:manage') @Feature('privacy_tools')
  retention(@Me() me: Principal) { return this.privacy.retention(me.orgId); }

  @Post('privacy/retention') @HttpCode(200) @Perm('privacy:manage') @Feature('privacy_tools')
  setRetention(@Me() me: Principal, @Body() b: unknown) { return this.privacy.setRetention(me, parse(RetentionSchema, b)); }

  @Post('privacy/retention/apply') @HttpCode(200) @Perm('privacy:manage') @Feature('privacy_tools')
  apply(@Me() me: Principal) { return this.privacy.applyRetention(me); }

  @Get('privacy/export') @Perm('privacy:manage') @Feature('privacy_tools')
  export(@Me() me: Principal) { return this.privacy.exportAll(me); }

  @Post('privacy/erase-user') @HttpCode(200) @Perm('privacy:manage') @Feature('privacy_tools')
  erase(@Me() me: Principal, @Body() b: unknown) { const x = parse(Erase, b); return this.privacy.eraseUser(me, x.userId, x.confirm); }
}
