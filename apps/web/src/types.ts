export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Role = 'viewer' | 'analyst' | 'approver' | 'admin';
export interface Me { userId: string; orgId: string; role: Role; email: string }
export interface Finding {
  id: string; scanId: string; kind: 'vulnerability' | 'secret'; ruleId: string; title: string; description: string;
  baseSeverity: Severity; severity: Severity; exposureScore: number; assetName?: string; location?: string;
  status: 'open' | 'suppressed' | 'remediating' | 'resolved'; suppressionReason?: string; rationale: string[];
  maskedSecret?: string; credentialId?: string; remediationPlanIds: string[]; createdAt: string;
}
export interface Asset { id: string; name: string; internetFacing: boolean; behindGateway: boolean; handlesCriticalData: boolean; environment: 'prod' | 'staging' | 'dev' }
export interface Summary { totals: { open: number; suppressed: number; secrets: number }; bySeverity: Record<Severity, number>; byAsset: Record<string, number> }
export interface Plan { id: string; kind: 'waf' | 'iam' | 'isolation' | 'rotation' | 'terraform'; targetRef: string; action: string; params: Record<string, any>; diff: string; terraform?: string; planHash: string; applied: boolean; destructive: boolean; createdAt: string; tf?: { stack: string; summary?: { add: number; change: number; destroy: number }; text?: string; planRef?: string; noChanges?: boolean } }
export interface StepView { name: string; action: string; status: 'pending' | 'running' | 'succeeded' | 'failed' | 'skipped' | 'awaiting_approval'; destructive: boolean; attempts?: number; error?: string; output?: Record<string, unknown>; startedAt?: string; finishedAt?: string }
export interface Approval {
  id: string; executionId: string; stepName: string; planId: string; planHash: string; status: 'pending' | 'approved' | 'rejected';
  requestedAt: string; decidedBy?: string; decidedAt?: string; comment?: string; signature?: string; plan?: Plan;
  finding?: { id: string; title: string; severity: Severity };
  execution?: { id: string; workflowKey: string; status: string; requestedBy: string; incidentId?: string; steps: StepView[] };
}
export interface Execution { id: string; workflowKey: string; workflowVersion: number; status: 'queued' | 'running' | 'awaiting_approval' | 'succeeded' | 'failed' | 'rejected'; steps: StepView[]; context: { requestedBy?: string; credentialId?: string }; incidentId?: string; createdAt: string; updatedAt: string }
export interface Credential { id: string; name: string; service: string; kind: 'api_key' | 'master_secret'; currentVersion: number; maskedValue: string; status: 'active' | 'exposed' | 'revoked' }
export interface Incident { id: string; severity: Severity; target: string; status: string; summary?: string; executionId?: string; createdAt: string; anomaly?: { kind: string; source: string; count: number; windowSec: number } }
export interface Forensics { incident: { id: string; severity: Severity; target: string; summary?: string }; snapshot: { id: string; sha256: string; capturedAt: string; integrity: string }; evidence: { metrics: Record<string, unknown>; logs: string[]; containerState: Record<string, unknown> } }
export interface IdentityAudit { id: string; roleName: string; critical: boolean; granted: string[]; used: string[]; unused: string[]; usageRatio: number; proposedPolicy: { statements: Array<{ actions: string[]; resources: string[] }> }; createdAt: string }
export interface AuditEntry { id: string; seq: number; at: string; actor: string; event: string; data: unknown; prevHash: string; hash: string }
export interface Trace { finding: Finding; scan?: { id: string; source: string; format: string; reportRef: string; reportSha256: string; createdAt: string }; plans: Plan[] }
