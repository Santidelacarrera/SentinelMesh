import { BadRequestException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DryRunPlan, PolicyDoc } from '../store/models';
import { ObjectStorage } from '../storage/object-storage';
import { HclFiles, filesHash, iamFiles, wafFiles } from './hcl';
import { TerraformError, TerraformRunner, TfConfig } from './runner';
import { TerminalStepError } from '../workflow/errors';

export type TfInfo = NonNullable<DryRunPlan['tf']>;
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

export function tfConfigFromEnv(env = process.env): TfConfig {
  return {
    bin: env.TF_BIN ?? 'terraform', stateDir: env.TF_STATE_DIR ?? join(tmpdir(), 'sentinelmesh-tfstate'), backendHcl: env.TF_BACKEND_HCL,
    providerHcl: env.TF_PROVIDER_HCL ?? `provider "aws" {\n  region = ${JSON.stringify(env.AWS_REGION ?? 'us-east-1')}\n}\n`,
    awsProviderVersion: env.TF_AWS_VERSION ?? '~> 5.0', cliConfigFile: env.TF_CLI_CONFIG_FILE,
    passEnv: (env.TF_PASS_ENV ?? 'AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN,AWS_REGION,AWS_DEFAULT_REGION,AWS_PROFILE,AWS_ROLE_ARN,AWS_WEB_IDENTITY_TOKEN_FILE,AWS_CONTAINER_CREDENTIALS_RELATIVE_URI').split(','),
    timeoutMs: Number(env.TF_TIMEOUT_MS ?? 180_000),
  };
}

/**
 * Turns waf/iam plans into real Terraform: the HCL shown to the approver is the HCL that is planned and, after signature, applied
 * (`terraform apply <saved plan>`). The approval hash covers the planned resource changes, not just our description of them.
 */
export class TerraformPlanner {
  readonly enabled: boolean;
  private runner?: TerraformRunner;
  constructor(private storage: ObjectStorage, cfg?: TfConfig) {
    this.enabled = process.env.TERRAFORM_ENABLED === '1' || !!cfg;
    if (this.enabled) this.runner = new TerraformRunner(cfg ?? tfConfigFromEnv());
  }

  /** HCL for a kind (always available, also for previews when Terraform is not installed). */
  filesFor(kind: DryRunPlan['kind'], targetRef: string, params: Record<string, unknown>): { stack: string; files: HclFiles } | undefined {
    try {
      if (kind === 'waf') {
        const rule = (params['rule'] ?? {}) as { name?: string; action?: string; priority?: number; addresses?: string[] };
        return { stack: `waf-${rule.name}`, files: wafFiles({ name: rule.name ?? '', action: rule.action, priority: rule.priority, addresses: rule.addresses ?? [] }) };
      }
      if (kind === 'iam') {
        const proposed = params['proposed'] as PolicyDoc | undefined;
        return { stack: `iam-${targetRef}`, files: iamFiles({ roleName: String(params['roleName'] ?? targetRef), proposed: { version: proposed?.version ?? '2012-10-17', statements: proposed?.statements ?? [] }, replacePolicyName: params['replacePolicyName'] as string | undefined }) };
      }
    } catch (e) { throw new BadRequestException((e as Error).message); }
    return undefined;
  }

  async plan(orgId: string, planId: string, stack: string, files: HclFiles): Promise<TfInfo> {
    const base = { stack: `${orgId}-${stack}`.replace(/[^\w-]/g, '_'), files, filesHash: filesHash(files) };
    if (!this.runner) return base;
    try {
      const r = await this.runner.plan(base.stack, files);
      const planRef = `terraform/${orgId}/${planId}.tfplan`;
      await this.storage.put(planRef, r.planFile);
      return { ...base, changesHash: r.changesHash, summary: r.summary, text: r.text, planRef, planSha256: sha(r.planFile), noChanges: r.exitCode === 0 };
    } catch (e) {
      if (e instanceof TerraformError) throw new BadRequestException(`terraform ${e.stage} failed: ${e.message}`);
      throw e;
    }
  }

  async apply(plan: DryRunPlan): Promise<{ ref: string; log: string; alreadyApplied: boolean }> {
    const tf = plan.tf;
    if (!this.runner || !tf?.planRef) throw new TerminalStepError('plan has no saved Terraform plan');
    if (filesHash(tf.files) !== tf.filesHash) throw new TerminalStepError('Terraform files changed after approval was requested');
    const bytes = await this.storage.get(tf.planRef);
    if (!bytes || sha(bytes) !== tf.planSha256) throw new TerminalStepError('saved Terraform plan is missing or was altered');
    const r = await this.runner.apply(tf.stack, tf.files, bytes);
    return { ref: `terraform:${tf.stack}:${plan.id}`, log: r.log, alreadyApplied: r.alreadyApplied };
  }
}
