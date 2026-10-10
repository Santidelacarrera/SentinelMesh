import { Module } from '@nestjs/common';
import { ApiController } from './api.controllers';
import { Db } from './store/db';
import { AuditTrail } from './audit/audit-trail';
import { AuthService, RolesGuard } from './auth/auth';
import { ApprovalSigner } from './approvals/signer';
import { ApprovalsService } from './approvals/approvals.service';
import { DryRunService } from './remediation/dryrun.service';
import { RemediationService } from './remediation/remediation.service';
import { IncidentsService } from './incidents/incidents.service';
import { IngestService } from './ingest/ingest.service';
import { AnalyticsClient } from './analytics/analytics.client';
import { WorkflowService } from './workflow/workflow.service';
import { WorkflowEngine } from './workflow/engine';
import { CoreHandlers } from './workflow/handlers';
import { PORTS } from './workflow/ports';
import { SimulatedForensics, SimulatedHealth, SimulatedInfra, SimulatedSecrets } from './workflow/simulated';
import { JOB_QUEUE, BullQueue, MemoryQueue } from './queue/queue';
import { FsObjectStorage, MemoryObjectStorage, OBJECT_STORAGE } from './storage/object-storage';

@Module({
  controllers: [ApiController],
  providers: [
    Db, AuditTrail, AuthService, RolesGuard, ApprovalSigner, ApprovalsService, DryRunService, RemediationService, IncidentsService,
    IngestService, WorkflowService, WorkflowEngine, CoreHandlers,
    { provide: AnalyticsClient, useFactory: () => new AnalyticsClient() },
    { provide: JOB_QUEUE, useFactory: () => (process.env.REDIS_URL ? new BullQueue(process.env.REDIS_URL) : new MemoryQueue(5, 500)) },
    { provide: OBJECT_STORAGE, useFactory: () => (process.env.OBJECT_STORE_DIR ? new FsObjectStorage(process.env.OBJECT_STORE_DIR) : new MemoryObjectStorage()) },
    // Simulated ports: real AWS/Vault/K8s adapters implement the same interfaces (see docs/architecture.md).
    { provide: PORTS.SECRETS, inject: [ApprovalSigner], useFactory: (s: ApprovalSigner) => { const x = new SimulatedSecrets((p) => s.assertProof(p)); return x; } },
    { provide: PORTS.HEALTH, useFactory: () => new SimulatedHealth() },
    { provide: PORTS.INFRA, inject: [ApprovalSigner], useFactory: (s: ApprovalSigner) => new SimulatedInfra((p) => s.assertProof(p)) },
    { provide: PORTS.FORENSICS, useFactory: () => new SimulatedForensics() },
  ],
})
export class AppModule {}
