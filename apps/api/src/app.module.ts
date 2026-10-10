import { Controller, Get, MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { RateLimit, SecurityHeaders } from './http-hardening';
import { ApiController } from './api.controllers';
import { Db } from './store/db';
import { PgBackend } from './store/pg';
import { AuditTrail } from './audit/audit-trail';
import { AuthService, RolesGuard } from './auth/auth';
import { ApprovalSigner } from './approvals/signer';
import { ApprovalsService } from './approvals/approvals.service';
import { DryRunService } from './remediation/dryrun.service';
import { TerraformPlanner } from './terraform/planner';
import { OBJECT_STORAGE, ObjectStorage } from './storage/object-storage';
import { RemediationService } from './remediation/remediation.service';
import { IncidentsService } from './incidents/incidents.service';
import { IngestService } from './ingest/ingest.service';
import { AnalyticsClient } from './analytics/analytics.client';
import { WorkflowService } from './workflow/workflow.service';
import { WorkflowEngine } from './workflow/engine';
import { CoreHandlers } from './workflow/handlers';
import { portProviders } from './ports.config';
import { EXECUTION_LOCK, MemoryLock, RedisLock } from './workflow/lock';
import Redis from 'ioredis';
import { JOB_QUEUE, BullQueue, MemoryQueue } from './queue/queue';

@Controller()
class HealthController {
  @Get('healthz') live() { return { ok: true }; }
}

@Module({
  controllers: [ApiController, HealthController],
  providers: [
    Db, PgBackend, AuditTrail, AuthService, RolesGuard, ApprovalSigner, ApprovalsService, DryRunService, RemediationService, IncidentsService,
    IngestService, WorkflowService, WorkflowEngine, CoreHandlers,
    { provide: AnalyticsClient, useFactory: () => new AnalyticsClient() },
    { provide: JOB_QUEUE, useFactory: () => (process.env.REDIS_URL ? new BullQueue(process.env.REDIS_URL) : new MemoryQueue(5, 500)) },
    { provide: EXECUTION_LOCK, useFactory: () => (process.env.REDIS_URL ? new RedisLock(new Redis(process.env.REDIS_URL)) : new MemoryLock()) },
    { provide: TerraformPlanner, inject: [OBJECT_STORAGE], useFactory: (st: ObjectStorage) => new TerraformPlanner(st) },
    ...portProviders,
  ],
})
export class AppModule implements NestModule {
  configure(c: MiddlewareConsumer) { c.apply(SecurityHeaders, RateLimit).forRoutes('*'); }
}
