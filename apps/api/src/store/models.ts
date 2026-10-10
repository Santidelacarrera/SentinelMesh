export type SecOpsRole = 'viewer' | 'analyst' | 'approver' | 'admin';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Org { id: string; name: string }
export interface User { id: string; orgId: string; email: string; role: SecOpsRole }

export interface VulnerabilityScan { id: string; orgId: string; source: string; format: string; reportRef: string; reportSha256: string; findingCount: number; createdAt: string }

export interface AssetContext {
  id: string; orgId: string; name: string;
  internetFacing: boolean; behindGateway: boolean; handlesCriticalData: boolean;
  environment: 'prod' | 'staging' | 'dev';
}

export interface Finding {
  id: string; orgId: string; scanId: string; kind: 'vulnerability' | 'secret';
  fingerprint: string; ruleId: string; title: string; description: string;
  baseSeverity: Severity; severity: Severity; exposureScore: number;
  assetName?: string; location?: string;
  status: 'open' | 'suppressed' | 'remediating' | 'resolved';
  suppressionReason?: string; rationale: string[];
  maskedSecret?: string; credentialId?: string;
  remediationPlanIds: string[]; createdAt: string;
}

export interface CredentialRecord {
  id: string; orgId: string; name: string; service: string; kind: 'api_key' | 'master_secret';
  currentVersion: number; maskedValue: string; status: 'active' | 'exposed' | 'revoked'; healthcheckUrl?: string;
}

export interface IdentityAudit { id: string; orgId: string; roleName: string; critical: boolean; granted: string[]; used: string[]; unused: string[]; proposedPolicy: PolicyDoc; usageRatio: number; createdAt: string }
export interface PolicyDoc { version: string; statements: Array<{ effect: 'Allow'; actions: string[]; resources: string[] }> }
export interface AccessPolicy { id: string; orgId: string; roleName: string; policy: PolicyDoc; version: number }

export interface TrafficAnomaly { id: string; orgId: string; kind: 'brute_force' | 'request_spike'; source: string; target: string; count: number; windowSec: number; createdAt: string }
export interface SecurityIncident { id: string; orgId: string; anomalyId: string; severity: Severity; target: string; status: 'open' | 'awaiting_approval' | 'contained' | 'closed'; summary?: string; snapshotId?: string; executionId?: string; createdAt: string }
export interface ForensicSnapshot { id: string; orgId: string; incidentId: string; objectKey: string; sha256: string; items: string[]; capturedAt: string }

export type ActionType = 'create_credential' | 'update_secret_store' | 'healthcheck' | 'revoke_credential' | 'apply_waf_rule' | 'apply_iam_policy' | 'isolate_service' | 'collect_forensics' | 'summarize' | 'notify';
export interface DryRunPlan {
  id: string; orgId: string; kind: 'waf' | 'iam' | 'terraform' | 'rotation' | 'isolation';
  targetRef: string; action: ActionType; params: Record<string, unknown>;
  diff: string; terraform?: string; planHash: string; destructive: boolean; applied: boolean; sourceFindingId?: string; createdAt: string;
}

export type StepStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'skipped' | 'awaiting_approval';
export interface StepDef { name: string; action: ActionType; destructive?: boolean; params?: Record<string, unknown> }
export interface SecurityWorkflow { id: string; orgId: string; key: string; version: number; steps: StepDef[]; contentHash: string; createdAt: string }
export interface ExecutionStep { name: string; action: ActionType; destructive: boolean; status: StepStatus; attempts: number; output?: Record<string, unknown>; error?: string; startedAt?: string; finishedAt?: string }
export interface WorkflowExecution {
  id: string; orgId: string; workflowId: string; workflowKey: string; workflowVersion: number;
  status: 'queued' | 'running' | 'awaiting_approval' | 'succeeded' | 'failed' | 'rejected';
  context: Record<string, unknown>; steps: ExecutionStep[]; incidentId?: string; createdAt: string; updatedAt: string;
}
export interface SecOpsApproval {
  id: string; orgId: string; executionId: string; stepName: string; planId: string; planHash: string;
  status: 'pending' | 'approved' | 'rejected'; requestedAt: string;
  decidedBy?: string; decidedAt?: string; comment?: string; signature?: string;
}
export interface AuditEntry { id: string; orgId: string; seq: number; at: string; actor: string; event: string; data: unknown; prevHash: string; hash: string }
