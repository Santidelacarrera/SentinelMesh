import { Body, Controller, Get, Header, HttpCode, Param, Post, Query, Res, StreamableFile, UseGuards } from '@nestjs/common';
import { z } from 'zod';
import { Feature, Me, Perm, Principal, RolesGuard } from '../auth/auth';
import { parse } from '../common/zod';
import { CaseSchema, CasesService } from './cases.service';
import { EvidenceSchema, EvidenceService } from './evidence.service';
import { CorrelationService } from './correlation.service';

const Status = z.object({ status: z.enum(['new', 'investigating', 'contained', 'remediating', 'resolved', 'closed']), note: z.string().max(2000).optional() }).strict();
const Assign = z.object({ assigneeId: z.string().max(100).nullable() }).strict();
const Comment = z.object({ text: z.string().min(1).max(4000) }).strict();
const Link = z.object({ assetIds: z.array(z.string()).max(200).optional(), identityIds: z.array(z.string()).max(200).optional(), vulnerabilityIds: z.array(z.string()).max(200).optional(), signalIds: z.array(z.string()).max(500).optional() }).strict();
const Meta = z.object({ metadata: z.record(z.string(), z.unknown()), reason: z.string().min(5).max(500) }).strict();
const Export = z.object({ purpose: z.string().min(5).max(500) }).strict();
const Decide = z.object({ status: z.enum(['confirmed', 'dismissed']), note: z.string().min(5).max(1000) }).strict();

/** Incident management, forensic evidence with chain of custody, and cross-source correlation. */
@Controller('api/v1')
@UseGuards(RolesGuard)
@Feature('cases')
export class CasesController {
  constructor(private cases: CasesService, private evidence: EvidenceService, private corr: CorrelationService) {}

  @Get('cases') @Perm('cases:read')
  list(@Me() me: Principal, @Query() q: Record<string, string>) { return this.cases.list(me.orgId, q); }

  @Post('cases') @HttpCode(201) @Perm('cases:write')
  open(@Me() me: Principal, @Body() b: unknown) { return this.cases.open(me, parse(CaseSchema, b)); }

  @Get('cases/:id') @Perm('cases:read')
  detail(@Me() me: Principal, @Param('id') id: string) { return this.cases.detail(me.orgId, id); }

  @Get('cases/:id/timeline') @Perm('cases:read')
  timeline(@Me() me: Principal, @Param('id') id: string) { return this.cases.timeline(me.orgId, id); }

  @Post('cases/:id/status') @HttpCode(200) @Perm('cases:write')
  status(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { const x = parse(Status, b); return this.cases.setStatus(me, id, x.status, x.note); }

  @Post('cases/:id/assign') @HttpCode(200) @Perm('cases:write')
  assign(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.cases.assign(me, id, parse(Assign, b).assigneeId); }

  @Post('cases/:id/comments') @HttpCode(201) @Perm('cases:write')
  comment(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.cases.comment(me, id, parse(Comment, b).text); }

  @Post('cases/:id/links') @HttpCode(200) @Perm('cases:write')
  link(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.cases.link(me, id, parse(Link, b)); }

  // ── evidence ──
  @Get('cases/:id/evidence') @Perm('evidence:read')
  evidenceList(@Me() me: Principal, @Param('id') id: string) { return this.evidence.list(me.orgId, id); }

  @Post('cases/:id/evidence') @HttpCode(201) @Perm('evidence:write')
  addEvidence(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.evidence.add(me, id, parse(EvidenceSchema, b)); }

  @Post('cases/:id/evidence/export') @HttpCode(200) @Perm('evidence:export')
  exportEvidence(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.evidence.exportCase(me, id, parse(Export, b).purpose); }

  @Get('evidence/:id') @Perm('evidence:read')
  viewEvidence(@Me() me: Principal, @Param('id') id: string) { return this.evidence.view(me, id); }

  @Post('evidence/:id/verify') @HttpCode(200) @Perm('evidence:read')
  verify(@Me() me: Principal, @Param('id') id: string) { return this.evidence.verify(me, id); }

  @Get('evidence/:id/content') @Perm('evidence:export') @Header('Content-Type', 'application/octet-stream')
  async content(@Me() me: Principal, @Param('id') id: string, @Res({ passthrough: true }) res: { setHeader(k: string, v: string): void }) {
    const f = await this.evidence.download(me, id);
    res.setHeader('Content-Disposition', `attachment; filename="${f.name.replace(/[^\w.-]/g, '_')}"`); res.setHeader('X-Content-SHA256', f.sha256);
    return new StreamableFile(f.bytes);
  }

  @Post('evidence/:id/metadata') @HttpCode(200) @Perm('evidence:write')
  meta(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { const x = parse(Meta, b); return this.evidence.updateMetadata(me, id, x.metadata, x.reason); }

  // ── correlation ──
  @Get('correlations') @Perm('cases:read')
  correlations(@Me() me: Principal, @Query('status') status?: string) { return this.corr.list(me.orgId, status); }

  @Get('correlations/:id') @Perm('cases:read')
  correlation(@Me() me: Principal, @Param('id') id: string) { return this.corr.detail(me.orgId, id); }

  @Post('correlations/:id/decision') @HttpCode(200) @Perm('cases:write')
  decide(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { const x = parse(Decide, b); return this.corr.decide(me, id, x.status, x.note); }
}
