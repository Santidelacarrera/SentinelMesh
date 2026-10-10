/** Ports to the outside world. Real adapters (AWS/Vault/K8s) implement these; simulated ones ship for demo/tests. */
export interface ApprovalProof { approvalId: string; planId: string; planHash: string; decidedBy: string; decidedAt: string; signature: string }

export interface SecretProvider {
  /** Idempotent per key: replaying the same key returns the same version (crash-safe). */
  createVersion(credentialId: string, idempotencyKey: string): Promise<{ version: number }>;
  /** Points consumers (secret manager entry) to a version. */
  setActive(credentialId: string, version: number): Promise<void>;
  getActive(credentialId: string): Promise<number>;
  discardVersion(credentialId: string, version: number): Promise<void>;
  /** Destructive: only callable with a verified approval. */
  revokeVersion(credentialId: string, version: number, proof: ApprovalProof): Promise<void>;
  isValid(credentialId: string, version: number): Promise<boolean>;
}
export interface HealthChecker { check(service: string, credentialId: string, version: number): Promise<{ healthy: boolean; detail: string }> }

export interface InfraAdapter {
  applyWafRule(params: Record<string, unknown>, proof: ApprovalProof): Promise<{ ref: string }>;
  applyIamPolicy(params: Record<string, unknown>, proof: ApprovalProof): Promise<{ ref: string }>;
  isolateService(target: string, proof: ApprovalProof): Promise<{ ref: string }>;
}

export interface ForensicBundle { metrics: Record<string, unknown>; logs: string[]; containerState: Record<string, unknown> }
export interface ForensicCollector { collect(target: string, context: Record<string, unknown>): Promise<ForensicBundle> }

export const PORTS = { SECRETS: Symbol('SECRETS'), HEALTH: Symbol('HEALTH'), INFRA: Symbol('INFRA'), FORENSICS: Symbol('FORENSICS') };
