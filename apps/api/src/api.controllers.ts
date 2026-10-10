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

  @Get('iam/audits') @MinRole('viewer')
  iamAudits(@Me() me: Principal) { return this.db.identityAudits.list(me.orgId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)); }

  @Post('secrets/rotate') @MinRole('analyst') @HttpCode(202)
  rotate(@Me() me: Principal, @Body() body: unknown) { return this.rem.rotate(me, parse(RotateSchema, body)); }

  @Post('incidents/trigger') @MinRole('analyst') @HttpCode(202)
  trigger(@Me() me: Principal, @Body() body: unknown) { return this.inc.trigger(me, parse(TriggerSchema, body)); }

  @Post('remediations/simulate') @MinRole('analyst') @HttpCode(201)
  simulate(@Me() me: Principal, @Body() body: unknown) { return this.rem.simulate(me, parse(SimulateSchema, body)); }

  @Get('me') @MinRole('viewer')
  whoami(@Me() me: Principal) { return me; }

  @Get('findings') @MinRole('viewer')
  findings(@Me() me: Principal, @Query() q: Record<string, string>) {
    const sev = q['severity']?.split(','), text = q['q']?.toLowerCase();
    const all = this.db.findings.list(me.orgId, (f) =>
      (!sev || sev.includes(f.severity)) && (!q['kind'] || f.kind === q['kind']) && (!q['status'] || q['status'].split(',').includes(f.status)) && (!q['asset'] || f.assetName === q['asset'])
      && (!text || `${f.title} ${f.ruleId} ${f.assetName ?? ''} ${f.location ?? ''}`.toLowerCase().includes(text)))
      .sort((a, b) => b.exposureScore - a.exposureScore || b.createdAt.localeCompare(a.createdAt));
    const limit = Math.min(Number(q['limit'] ?? 100) || 100, 500), offset = Math.max(Number(q['offset'] ?? 0) || 0, 0);
    return { total: all.length, items: all.slice(offset, offset + limit) };
  }

  @Get('assets') @MinRole('viewer')
  assets(@Me() me: Principal) { return this.db.assets.list(me.orgId); }

  @Get('credentials') @MinRole('viewer')
  credentials(@Me() me: Principal) { return this.db.credentials.list(me.orgId); }

  @Get('executions') @MinRole('viewer')
  executions(@Me() me: Principal) {
    return this.db.executions.list(me.orgId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((e) => ({ ...e, context: { requestedBy: e.context['requestedBy'], credentialId: e.context['credentialId'], incidentId: e.context['incidentId'] } }));
  }

  @Get('incidents') @MinRole('viewer')
  incidents(@Me() me: Principal) {
    return this.db.incidents.list(me.orgId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((i) => ({ ...this.inc.getIncident(me.orgId, i.id), anomaly: this.db.anomalies.get(me.orgId, i.anomalyId) }));
  }

  @Get('approvals') @MinRole('viewer')
  inbox(@Me() me: Principal, @Query('status') status?: string) {
    return this.approvals.list(me.orgId, status).sort((a, b) => b.requestedAt.localeCompare(a.requestedAt)).map((a) => {
      const plan = this.db.plans.get(me.orgId, a.planId), ex = this.db.executions.get(me.orgId, a.executionId);
      const finding = plan?.sourceFindingId ? this.db.findings.get(me.orgId, plan.sourceFindingId) : undefined;
      return { ...a, plan, finding: finding && { id: finding.id, title: finding.title, severity: finding.severity },
        execution: ex && { id: ex.id, workflowKey: ex.workflowKey, status: ex.status, requestedBy: ex.context['requestedBy'], incidentId: ex.incidentId, steps: ex.steps.map((s) => ({ name: s.name, action: s.action, status: s.status, destructive: s.destructive })) } };
    });
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
