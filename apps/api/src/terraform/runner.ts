import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { HclFiles } from './hcl';
import { redactString } from '../common/mask';
import { stableStringify } from '../common/ids';

export interface TfConfig {
  bin: string;                       // terraform (or tofu) binary
  stateDir: string;                  // local backend root (single node); set `backendHcl` for S3/GCS/remote state shared by replicas
  backendHcl?: string;               // e.g. backend "s3" { bucket = "…" key = "…" dynamodb_table = "…" } — {{stack}} is replaced
  providerHcl: string;               // provider "aws" { … } block (endpoints/skip_* only for emulators)
  awsProviderVersion: string;        // e.g. "~> 5.0"
  cliConfigFile?: string;            // TF_CLI_CONFIG_FILE (provider mirror for air-gapped runners)
  passEnv?: string[];                // extra env vars forwarded to terraform (credentials). Everything else is dropped.
  timeoutMs?: number;
}
export interface TfChange { address: string; type: string; actions: string[]; before: unknown; after: unknown }
export interface TfPlanResult { exitCode: 0 | 2; summary: { add: number; change: number; destroy: number }; changes: TfChange[]; changesHash: string; text: string; planFile: Buffer }

const MAX_OUT = 8 * 1024 * 1024;
export class TerraformError extends Error { constructor(m: string, public stage: string) { super(m); } }

/**
 * Thin, safe wrapper around the terraform CLI. No shell, args as an array, scrubbed environment (the API's own secrets never
 * reach the child), throw-away working directory per call, hard timeout, output size cap, output redacted before it is returned.
 */
export class TerraformRunner {
  constructor(private c: TfConfig) {}

  private env(workdir: string) {
    const e: Record<string, string> = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: workdir, TF_IN_AUTOMATION: '1', TF_INPUT: '0', CHECKPOINT_DISABLE: '1' };
    if (this.c.cliConfigFile) e.TF_CLI_CONFIG_FILE = this.c.cliConfigFile;
    for (const k of this.c.passEnv ?? []) if (process.env[k] !== undefined) e[k] = process.env[k]!;
    return e;
  }

  private run(args: string[], cwd: string, stage: string, okCodes = [0], machine = false): Promise<{ code: number; out: string }> {
    return new Promise((resolve, reject) => {
      const p = execFile(this.c.bin, args, { cwd, env: this.env(cwd), timeout: this.c.timeoutMs ?? 180_000, maxBuffer: MAX_OUT, windowsHide: true }, (err, stdout, stderr) => {
        // human text is redacted before it can reach logs/UI; machine-readable JSON is parsed in-process and never stored or shown
        const out = machine ? String(stdout) : redactString(`${stdout}${stderr}`);
        const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? (err as { code: number }).code : -1) : 0;
        if (okCodes.includes(code)) resolve({ code, out });
        else reject(new TerraformError(`terraform ${args[0]} failed (${code === -1 ? (err as Error).message : `exit ${code}`}):\n${out.split('\n').slice(-40).join('\n')}`, stage));
      });
      p.stdin?.end();
    });
  }

  private async workspace(stack: string, files: HclFiles) {
    const dir = await mkdtemp(join(tmpdir(), 'sm-tf-'));
    const stateFile = join(this.c.stateDir, `${stack}.tfstate`);
    await mkdir(this.c.stateDir, { recursive: true });
    const backend = (this.c.backendHcl ?? `backend "local" {\n    path = ${JSON.stringify(stateFile)}\n  }`).replace(/\{\{stack\}\}/g, stack);
    await writeFile(join(dir, 'versions.tf'), `terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ${JSON.stringify(this.c.awsProviderVersion)}
    }
  }
  ${backend}
}
`);
    await writeFile(join(dir, 'provider.tf'), this.c.providerHcl);
    for (const [name, body] of Object.entries(files)) {
      if (!/^[\w.-]+\.tf$/.test(name)) throw new TerraformError(`illegal file name ${name}`, 'prepare');
      await writeFile(join(dir, name), body);
    }
    return dir;
  }

  /** `terraform plan` (read-only against the cloud). Returns the saved plan so the EXACT reviewed change can be applied later. */
  async plan(stack: string, files: HclFiles): Promise<TfPlanResult> {
    const dir = await this.workspace(stack, files);
    try {
      await this.run(['init', '-input=false', '-no-color'], dir, 'init');
      const v = await this.run(['validate', '-no-color'], dir, 'validate');
      void v;
      const pl = await this.run(['plan', '-input=false', '-no-color', '-lock-timeout=30s', '-detailed-exitcode', '-out=tfplan'], dir, 'plan', [0, 2]);
      const json = JSON.parse((await this.run(['show', '-json', 'tfplan'], dir, 'show', [0], true)).out) as { resource_changes?: Array<{ address: string; type: string; change: { actions: string[]; before: unknown; after: unknown } }> };
      const changes: TfChange[] = (json.resource_changes ?? []).filter((r) => !(r.change.actions.length === 1 && r.change.actions[0] === 'no-op')).map((r) => ({ address: r.address, type: r.type, actions: r.change.actions, before: r.change.before, after: r.change.after }));
      const summary = { add: 0, change: 0, destroy: 0 };
      for (const c of changes) { if (c.actions.includes('create')) summary.add++; else if (c.actions.includes('delete')) summary.destroy++; else if (c.actions.includes('update')) summary.change++; if (c.actions.includes('delete') && c.actions.includes('create')) summary.add++; }
      const text = (await this.run(['show', '-no-color', 'tfplan'], dir, 'show-text')).out;
      return { exitCode: pl.code as 0 | 2, summary, changes, changesHash: createHash('sha256').update(stableStringify(changes)).digest('hex'), text, planFile: await readFile(join(dir, 'tfplan')) };
    } finally { await rm(dir, { recursive: true, force: true }); }
  }

  /**
   * Applies the SAVED plan. Terraform itself refuses it if the config or the state moved since (stale plan), so nothing but the
   * reviewed change can run. If the plan is stale because it was already applied (crash after apply), a fresh plan with no changes counts as success.
   */
  async apply(stack: string, files: HclFiles, planFile: Buffer): Promise<{ applied: boolean; alreadyApplied: boolean; log: string }> {
    const dir = await this.workspace(stack, files);
    try {
      await this.run(['init', '-input=false', '-no-color'], dir, 'init');
      await writeFile(join(dir, 'tfplan'), planFile);
      try {
        const r = await this.run(['apply', '-input=false', '-no-color', '-lock-timeout=60s', 'tfplan'], dir, 'apply');
        return { applied: true, alreadyApplied: false, log: r.out.split('\n').slice(-12).join('\n') };
      } catch (e) {
        const probe = await this.run(['plan', '-input=false', '-no-color', '-detailed-exitcode'], dir, 'verify', [0, 2]).catch(() => undefined);
        if (probe?.code === 0) return { applied: true, alreadyApplied: true, log: 'no changes pending: the plan had already been applied' };
        throw e;
      }
    } finally { await rm(dir, { recursive: true, force: true }); }
  }
}
