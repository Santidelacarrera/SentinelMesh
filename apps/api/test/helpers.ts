import 'reflect-metadata';
import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { JOB_QUEUE, MemoryQueue } from '../src/queue/queue';
import { PORTS } from '../src/workflow/ports';
import { SimulatedHealth, SimulatedInfra, SimulatedSecrets } from '../src/workflow/simulated';
import { Db } from '../src/store/db';
import { AuditTrail } from '../src/audit/audit-trail';
import { WorkflowEngine } from '../src/workflow/engine';
import { OBJECT_STORAGE, MemoryObjectStorage } from '../src/storage/object-storage';
import { AuthService } from '../src/auth/auth';

process.env.HEALTH_RETRY_MS = '0';
delete process.env.ANALYTICS_URL;

export async function boot() {
  const mod = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(JOB_QUEUE).useValue(new MemoryQueue(4, 0))
    .overrideProvider(OBJECT_STORAGE).useValue(new MemoryObjectStorage())
    .compile();
  const app: INestApplication = mod.createNestApplication();
  await app.init();
  const auth = mod.get(AuthService);
  auth.register('other-org-analyst', { userId: 'u_x', orgId: 'org_other', role: 'analyst', email: 'x@other.test' });
  auth.register('admin-key', { userId: 'u_admin', orgId: 'org_acme', role: 'admin', email: 'admin@acme.test' });
  const http = request(app.getHttpServer());
  const as = (key: string) => ({
    get: (p: string) => http.get(p).set('x-api-key', key),
    post: (p: string, b?: unknown) => http.post(p).set('x-api-key', key).send(b as object),
  });
  return {
    app, http, as, analyst: as('dev-analyst'), approver: as('dev-approver'), viewer: as('dev-viewer'), other: as('other-org-analyst'),
    queue: mod.get<MemoryQueue>(JOB_QUEUE),
    secrets: mod.get<SimulatedSecrets>(PORTS.SECRETS), health: mod.get<SimulatedHealth>(PORTS.HEALTH), infra: mod.get<SimulatedInfra>(PORTS.INFRA),
    db: mod.get(Db), audit: mod.get(AuditTrail), engine: mod.get(WorkflowEngine), storage: mod.get<MemoryObjectStorage>(OBJECT_STORAGE),
  };
}
export type Env = Awaited<ReturnType<typeof boot>>;
export const ORG = 'org_acme';
