import { ApprovalProof, ForensicBundle, ForensicCollector, HealthChecker, InfraAdapter, SecretProvider } from './ports';

export class SimulatedSecrets implements SecretProvider {
  versions = new Map<string, Map<number, 'valid' | 'revoked'>>();
  active = new Map<string, number>();
  idem = new Map<string, number>();
  calls: string[] = [];
  constructor(private proofCheck: (p: ApprovalProof) => void | Promise<void> = () => {}) {}
  seed(id: string) { this.versions.set(id, new Map([[1, 'valid']])); this.active.set(id, 1); }
  async createVersion(id: string, key: string) {
    this.calls.push(`create:${key}`);
    const hit = this.idem.get(key); if (hit) return { version: hit };
    const m = this.versions.get(id) ?? new Map(); const v = Math.max(0, ...m.keys()) + 1;
    m.set(v, 'valid'); this.versions.set(id, m); this.idem.set(key, v); return { version: v };
  }
  async setActive(id: string, v: number) { this.calls.push(`active:${v}`); this.active.set(id, v); }
  async getActive(id: string) { return this.active.get(id) ?? 1; }
  async discardVersion(id: string, v: number) { this.calls.push(`discard:${v}`); this.versions.get(id)?.delete(v); }
  async revokeVersion(id: string, v: number, proof: ApprovalProof) { await this.proofCheck(proof); this.calls.push(`revoke:${v}`); this.versions.get(id)?.set(v, 'revoked'); }
  async isValid(id: string, v: number) { return this.versions.get(id)?.get(v) === 'valid'; }
}

export class SimulatedHealth implements HealthChecker {
  failFor = new Set<string>(); // `${credentialId}:${version}`
  checks: string[] = [];
  async check(service: string, id: string, version: number) {
    this.checks.push(`${service}:${version}`);
    const bad = this.failFor.has(`${id}:${version}`);
    return { healthy: !bad, detail: bad ? 'HTTP 503 from /healthz' : 'HTTP 200 from /healthz' };
  }
}

export class SimulatedInfra implements InfraAdapter {
  applied: Array<{ op: string; arg: unknown }> = [];
  constructor(private proofCheck: (p: ApprovalProof) => void | Promise<void> = () => {}) {}
  async applyWafRule(params: Record<string, unknown>, proof: ApprovalProof) { await this.proofCheck(proof); this.applied.push({ op: 'waf', arg: params }); return { ref: 'waf-sim-1' }; }
  async applyIamPolicy(params: Record<string, unknown>, proof: ApprovalProof) { await this.proofCheck(proof); this.applied.push({ op: 'iam', arg: params }); return { ref: 'iam-sim-1' }; }
  async isolateService(target: string, proof: ApprovalProof) { await this.proofCheck(proof); this.applied.push({ op: 'isolate', arg: target }); return { ref: `sg-isolate-${target}` }; }
}

export class SimulatedForensics implements ForensicCollector {
  async collect(target: string, ctx: Record<string, unknown>): Promise<ForensicBundle> {
    return {
      metrics: { target, capturedAtMs: Date.now(), cpuPct: 91, reqPerSec: ctx['count'] ?? 0 },
      logs: (ctx['gatewayLogs'] as string[] | undefined) ?? [],
      containerState: { target, status: 'running', restarts: 0, image: `registry.local/${target}:latest` },
    };
  }
}
