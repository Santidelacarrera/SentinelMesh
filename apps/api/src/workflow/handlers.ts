import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { WorkflowEngine, StepCtx, TerminalStepError } from './engine';
import { PORTS, SecretProvider, HealthChecker, InfraAdapter } from './ports';
import { Db } from '../store/db';
import { ActionType } from '../store/models';

const outputOf = (c: StepCtx, action: ActionType) => c.execution.steps.find((s) => s.action === action && s.output)?.output as Record<string, any> | undefined;

/** Built-in actions. Destructive ones receive a verified `proof`; adapters re-verify it. */
@Injectable()
export class CoreHandlers implements OnModuleInit {
  constructor(
    private engine: WorkflowEngine, private db: Db,
    @Inject(PORTS.SECRETS) private secrets: SecretProvider, @Inject(PORTS.HEALTH) private health: HealthChecker, @Inject(PORTS.INFRA) private infra: InfraAdapter,
  ) {}

  onModuleInit() {
    const e = this.engine;
    e.register('create_credential', async (c) => {
      const id = String(c.input['credentialId']);
      await this.secrets.adopt?.(id);
      const previousVersion = await this.secrets.getActive(id);
      const { version } = await this.secrets.createVersion(id, c.idempotencyKey);
      return { previousVersion, newVersion: version };
    });
    e.register('update_secret_store', async (c) => {
      const id = String(c.input['credentialId']); const created = outputOf(c, 'create_credential')!;
      await this.secrets.setActive(id, created['newVersion']);
      return { active: created['newVersion'] };
    });
    e.register('healthcheck', async (c) => {
      const id = String(c.input['credentialId']); const cred = this.db.credentials.get(c.orgId, id);
      const created = outputOf(c, 'create_credential')!;
      let last = { healthy: false, detail: 'no attempt' };
      for (let i = 0; i < 3; i++) {
        last = await this.health.check(cred?.service ?? id, id, created['newVersion']);
        if (last.healthy) return { healthy: true, detail: last.detail, attempts: i + 1 };
        const wait = Number(process.env.HEALTH_RETRY_MS ?? 1000);
        if (wait) await new Promise((r) => setTimeout(r, wait));
      }
      // Zero-downtime guarantee: consumers go back to the old, still-valid credential before we give up.
      await this.secrets.setActive(id, created['previousVersion']);
      await this.secrets.discardVersion(id, created['newVersion']);
      throw new TerminalStepError(`healthcheck failed (${last.detail}); rolled back to v${created['previousVersion']}, old credential untouched`);
    });
    e.register('revoke_credential', async (c) => {
      const id = String(c.input['credentialId']); const created = outputOf(c, 'create_credential')!;
      const active = await this.secrets.getActive(id);
      if (created['previousVersion'] === active) throw new TerminalStepError('refusing to revoke the active credential');
      if (!(await this.secrets.isValid(id, active))) throw new TerminalStepError('active credential is not valid; refusing to revoke the fallback');
      await this.secrets.revokeVersion(id, created['previousVersion'], c.proof!);
      this.db.credentials.update(c.orgId, id, (r) => { r.currentVersion = active; r.status = 'active'; });
      return { revoked: created['previousVersion'], active };
    });
    e.register('apply_waf_rule', async (c) => this.infra.applyWafRule(c.plan!.params, c.proof!));
    e.register('apply_iam_policy', async (c) => this.infra.applyIamPolicy(c.plan!.params, c.proof!));
    e.register('isolate_service', async (c) => this.infra.isolateService(c.plan!.targetRef, c.proof!));
  }
}
