import { Body, Controller, Get, HttpCode, NotFoundException, Param, Post, Query, UseGuards } from '@nestjs/common';
import { z } from 'zod';
import { AssetSchema, IngestSchema, IngestService } from './ingest/ingest.service';
import { IamAuditSchema, RemediationService, RotateSchema, SimulateSchema } from './remediation/remediation.service';
import { IncidentsService, TriggerSchema } from './incidents/incidents.service';
import { ApprovalsService } from './approvals/approvals.service';
import { AuditTrail } from './audit/audit-trail';
import { Db } from './store/db';
import { Me, MinRole, Principal, RolesGuard } from './auth/auth';
import { parse } from './common/zod';

const DecisionSchema = z.object({ decision: z.enum(['approved', 'rejected']), comment: z.string().max(2000).optional() }).strict();

@Controller('api/v1')
@UseGuards(RolesGuard)
export class ApiController {
  constructor(private ingest: IngestService, private rem: RemediationService, private inc: IncidentsService, private approvals: ApprovalsService, private audit: AuditTrail, private db: Db) {}

  @Post('scans/ingest') @MinRole('analyst') @HttpCode(201)
  ingestScan(@Me() me: Principal, @Body() body: unknown) { return this.ingest.ingest(me.orgId, me.userId, parse(IngestSchema, body)); }

  @Post('assets') @MinRole('analyst') @HttpCode(201)
  asset(@Me() me: Principal, @Body() body: unknown) { return this.ingest.upsertAsset(me.orgId, parse(AssetSchema, body)); }

  @Get('exposures/summary') @MinRole('viewer')
  summary(@Me() me: Principal) { return this.ingest.summary(me.orgId); }

  @Get('findings/:id/trace') @MinRole('viewer')
  trace(@Me() me: Principal, @Param('id') id: string) { return this.ingest.trace(me.orgId, id); }

  @Post('iam/audit-roles') @MinRole('analyst') @HttpCode(201)
  auditRoles(@Me() me: Principal, @Body() body: unknown) { return this.rem.auditRole(me, parse(IamAuditSchema, body)); }

  @Post('secrets/rotate') @MinRole('analyst') @HttpCode(202)
  rotate(@Me() me: Principal, @Body() body: unknown) { return this.rem.rotate(me, parse(RotateSchema, body)); }

  @Post('incidents/trigger') @MinRole('analyst') @HttpCode(202)
  trigger(@Me() me: Principal, @Body() body: unknown) { return this.inc.trigger(me, parse(TriggerSchema, body)); }

  @Post('remediations/simulate') @MinRole('analyst') @HttpCode(201)
  simulate(@Me() me: Principal, @Body() body: unknown) { return this.rem.simulate(me, parse(SimulateSchema, body)); }

  @Get('approvals') @MinRole('viewer')
  inbox(@Me() me: Principal, @Query('status') status?: string) {
    return this.approvals.list(me.orgId, status).map((a) => ({ ...a, plan: this.db.plans.get(me.orgId, a.planId) }));
  }

  @Post('approvals/:id/decision') @MinRole('approver') @HttpCode(200)
  decide(@Me() me: Principal, @Param('id') id: string, @Body() body: unknown) {
    const b = parse(DecisionSchema, body); return this.approvals.decide(me, id, b.decision, b.comment);
  }

  @Get('executions/:id') @MinRole('viewer')
  execution(@Me() me: Principal, @Param('id') id: string) {
    const e = this.db.executions.get(me.orgId, id); if (!e) throw new NotFoundException(); return e;
  }

  @Get('executions/:id/forensics') @MinRole('viewer')
  forensics(@Me() me: Principal, @Param('id') id: string) { return this.inc.forensics(me.orgId, id); }

  @Get('incidents/:id') @MinRole('viewer')
  incident(@Me() me: Principal, @Param('id') id: string) { return this.inc.getIncident(me.orgId, id); }

  @Get('audit') @MinRole('viewer')
  auditLog(@Me() me: Principal) { return { verify: this.audit.verify(me.orgId), entries: this.audit.list(me.orgId) }; }
}
