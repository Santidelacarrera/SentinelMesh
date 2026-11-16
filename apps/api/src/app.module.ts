import { Controller, Get, MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { RowNotFoundFilter } from './common/not-found.filter';
import { RateLimit, SecurityHeaders } from './http-hardening';
import { CorrelationMiddleware } from './common/correlation';
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
import { AuthController } from './auth/auth.controller';
import { AccountsService, SECRET_BOX } from './auth/accounts.service';
import { Entitlements } from './platform/entitlements';
import { SecretBox } from './common/crypto';
import { CtemController } from './ctem/ctem.controller';
import { IamController } from './iam/iam.controller';
import { IamService } from './iam/iam.service';
import { ConnectorsController } from './connectors/connectors.controller';
import { ConnectorsService } from './connectors/connectors.service';
import { SignalsService } from './signals/signals.service';
import { EventBus } from './common/events';
import { CasesController } from './cases/cases.controller';
import { CasesService } from './cases/cases.service';
import { EvidenceService } from './cases/evidence.service';
import { CorrelationService } from './cases/correlation.service';
import { NotificationsService, MAILER, SmtpMailer } from './notifications/notifications.service';
import { PlaybooksService, SOAR_EXECUTOR, LabExecutor } from './soar/playbooks.service';
import { SoarController, NotificationsController } from './soar/soar.controller';
import { CtemService, DNS_RESOLVER, TLS_PROBE, defaultDns, defaultTlsProbe } from './ctem/ctem.service';

@Controller()
class HealthController {
  @Get('healthz') live() { return { ok: true }; }
}

@Module({
  controllers: [ApiController, AuthController, CtemController, IamController, ConnectorsController, CasesController, SoarController, NotificationsController, HealthController],
  providers: [
    Db, PgBackend, AuditTrail, AuthService, RolesGuard, AccountsService, Entitlements,
    { provide: APP_FILTER, useClass: RowNotFoundFilter },
    EventBus, CtemService, IamService, SignalsService, ConnectorsService, CasesService, EvidenceService, CorrelationService, NotificationsService, PlaybooksService, LabExecutor,
    { provide: MAILER, useFactory: () => new SmtpMailer() }, { provide: SOAR_EXECUTOR, useExisting: LabExecutor }, { provide: DNS_RESOLVER, useValue: defaultDns }, { provide: TLS_PROBE, useValue: defaultTlsProbe },
    { provide: SECRET_BOX, useFactory: () => SecretBox.fromEnv() }, ApprovalSigner, ApprovalsService, DryRunService, RemediationService, IncidentsService,
    IngestService, WorkflowService, WorkflowEngine, CoreHandlers,
    { provide: AnalyticsClient, useFactory: () => new AnalyticsClient() },
    { provide: JOB_QUEUE, useFactory: () => (process.env.REDIS_URL ? new BullQueue(process.env.REDIS_URL) : new MemoryQueue(5, 500)) },
    { provide: EXECUTION_LOCK, useFactory: () => (process.env.REDIS_URL ? new RedisLock(new Redis(process.env.REDIS_URL)) : new MemoryLock()) },
    { provide: TerraformPlanner, inject: [OBJECT_STORAGE], useFactory: (st: ObjectStorage) => new TerraformPlanner(st) },
    ...portProviders,
  ],
})
export class AppModule implements NestModule {
  configure(c: MiddlewareConsumer) { c.apply(CorrelationMiddleware, SecurityHeaders, RateLimit).forRoutes('*'); }
}
