import type { Severity } from './models';

/** Organisation-scoped enterprise domain (CTEM, IAM, correlation, cases, evidence, SOAR, notifications, connectors, reports). */

// ───────── platform / tenancy / identity of the product itself ─────────
export type Plan = 'starter' | 'business' | 'enterprise';
/** Lives in the platform org (`org_platform`); `id` is the tenant's org id. */
export interface OrgProfile { id: string; orgId: string; name: string; plan: Plan; status: 'active' | 'suspended'; retentionDays: number; createdAt: string; createdBy: string }
export interface UserAccount {
  id: string; orgId: string; email: string; role: string; customRoles: string[]; passwordHash: string; passwordChangedAt: string;
  mfa?: { secretEnc: string; enabled: boolean; pendingSecretEnc?: string; lastStep?: number }; failedLogins: number; lockedUntil?: string;
  status: 'active' | 'disabled'; createdAt: string; lastLoginAt?: string; previousPasswordHashes: string[];
}
export interface Session {
  id: string; orgId: string; userId: string; family: string; accessHash: string; refreshHash: string; usedRefreshHashes: string[];
  expiresAt: string; refreshExpiresAt: string; revokedAt?: string; revokedReason?: string; createdAt: string; lastSeenAt: string; ip?: string; userAgent?: string;
}
export interface CustomRole { id: string; orgId: string; name: string; permissions: string[]; createdAt: string }
export interface PasswordReset { id: string; orgId: string; userId: string; tokenHash: string; expiresAt: string; usedAt?: string; issuedBy: string }
export interface Setting { id: string; orgId: string; key: string; value: unknown; updatedAt: string; updatedBy: string }

// ───────── CTEM ─────────
export const ASSET_TYPES = ['domain', 'subdomain', 'ip', 'server', 'web_app', 'api', 'container', 'k8s_cluster', 'cloud_service', 'repository', 'database', 'endpoint', 'other'] as const;
export type AssetType = (typeof ASSET_TYPES)[number];
export type Criticality = 'low' | 'medium' | 'high' | 'critical';
export interface InventoryAsset {
  id: string; orgId: string; type: AssetType; identifier: string; name: string; source: string;
  firstSeen: string; lastSeen: string; status: 'active' | 'stale' | 'retired'; criticality: Criticality;
  owner?: string; internetFacing: boolean; environment: 'prod' | 'staging' | 'dev'; tags: string[]; controls: string[];
  ownership: { status: 'unverified' | 'verified'; method?: 'dns_txt' | 'manual_attestation' | 'connector'; challenge?: string; verifiedAt?: string; verifiedBy?: string };
  /** Active probes (TLS check) are only ever allowed against verified, in-scope assets. */
  inScope: boolean;
}
export type RelationKind = 'runs_on' | 'depends_on' | 'hosts' | 'trusts' | 'member_of' | 'authenticates_to' | 'stores_data_in' | 'can_assume' | 'admin_of' | 'has_access' | 'exposes';
/** Edge of the exposure graph. `from`/`to` are inventory-asset or identity ids. */
export interface Relation { id: string; orgId: string; from: string; to: string; kind: RelationKind; source: string; confidence: number; evidence?: string; createdAt: string }

export type Confidence = 'confirmed' | 'suspected' | 'unverified';
export interface PriorityFactor { name: string; points: number; detail: string }
export interface PriorityResult { score: number; level: 'immediate' | 'high' | 'medium' | 'low' | 'monitor'; factors: PriorityFactor[]; explanation: string; computedAt: string }
export interface Vulnerability {
  id: string; orgId: string; assetId: string; cve?: string; cwe?: string; title: string; description: string; severity: Severity;
  cvss?: { score: number; vector?: string; version?: string }; epss?: { score: number; percentile?: number; asOf?: string }; kev?: boolean; kevDueDate?: string;
  status: 'open' | 'in_progress' | 'mitigated' | 'resolved' | 'accepted'; confidence: Confidence; evidence: string[]; source: string;
  detectedAt: string; owner?: string; dueDate?: string; fingerprint: string; priority?: PriorityResult; resolvedAt?: string;
}
/** Imported threat-intelligence record (NVD / CISA KEV / EPSS). Only what the feed said; never invented. */
export interface IntelRecord { id: string; orgId: string; cve: string; cvss?: { score: number; vector?: string; version?: string }; cwe?: string; kev?: boolean; kevDueDate?: string; epss?: { score: number; percentile?: number; asOf?: string }; description?: string; sources: string[]; updatedAt: string }
export interface ExposureFinding {
  id: string; orgId: string; assetId: string; kind: 'open_port' | 'tls_expiring' | 'tls_invalid' | 'insecure_config' | 'forgotten_asset' | 'unnecessary_service';
  title: string; detail: string; severity: Severity; evidence: string[]; confidence: Confidence; status: 'open' | 'resolved'; firstSeen: string; lastSeen: string; fingerprint: string; resolvedAt?: string;
}
export interface ExposureEvent { id: string; orgId: string; assetId?: string; at: string; type: 'asset_discovered' | 'asset_changed' | 'asset_stale' | 'exposure_opened' | 'exposure_resolved' | 'ownership_verified'; detail: string }

// ───────── IAM ─────────
export interface Identity {
  id: string; orgId: string; kind: 'human' | 'service'; name: string; email?: string; provider: string; externalId: string;
  privileged: boolean; status: 'active' | 'disabled'; mfaEnabled?: boolean; lastActivityAt?: string; credentialAgeDays?: number;
  entitlements: string[]; usedEntitlements?: string[]; authMethods: string[]; createdAt: string; lastSeen: string; assetIds: string[];
}
export interface IdentityChange { id: string; orgId: string; identityId: string; at: string; kind: 'privilege_added' | 'privilege_removed' | 'status_changed' | 'mfa_changed' | 'discovered'; before?: unknown; after?: unknown; actor: string }
export interface IdentityRisk { identityId: string; code: 'inactive' | 'excessive_permissions' | 'privileged_no_mfa' | 'service_no_rotation' | 'weak_auth' | 'dangerous_trust' | 'privileged'; severity: Severity; detail: string; confidence: Confidence }

// ───────── signals, correlation, cases, evidence ─────────
export interface Signal {
  id: string; orgId: string; source: string; sourceId: string; dedupKey: string; kind: 'alert' | 'detection' | 'incident' | 'event'; title: string; severity: Severity; at: string;
  host?: string; ip?: string; user?: string; assetId?: string; identityId?: string; cves: string[]; domains: string[]; ips: string[]; raw?: unknown; correlationId?: string; createdAt: string;
}
export interface CorrelationReason { type: 'asset' | 'identity' | 'ip' | 'domain' | 'vulnerability' | 'time'; value: string; confidence: number; source: string }
export interface Correlation {
  id: string; orgId: string; signalIds: string[]; assetId?: string; identityId?: string; vulnerabilityIds: string[]; reasons: CorrelationReason[];
  /** 0..1 — a probabilistic link, never a confirmed fact unless a human sets `status: confirmed`. */
  confidence: number; status: 'probable' | 'confirmed' | 'dismissed'; caseId?: string; riskScore: number; recommendation: string[]; createdAt: string; updatedAt: string;
}
export type CaseStatus = 'new' | 'investigating' | 'contained' | 'remediating' | 'resolved' | 'closed';
export interface TimelineEntry { id: string; at: string; actor: string; kind: 'opened' | 'status' | 'assigned' | 'comment' | 'evidence' | 'signal' | 'action' | 'link' | 'note'; text: string; data?: unknown }
export interface Case {
  id: string; orgId: string; number: number; name: string; description: string; severity: Severity; status: CaseStatus;
  assetIds: string[]; identityIds: string[]; vulnerabilityIds: string[]; signalIds: string[]; evidenceIds: string[]; correlationId?: string;
  assigneeId?: string; recommendations: string[]; actions: Array<{ at: string; actor: string; action: string; result: string }>; timeline: TimelineEntry[];
  source: 'manual' | 'correlation' | 'playbook'; risk?: number; openedAt: string; closedAt?: string; createdBy: string;
}
export interface CustodyEntry { at: string; actor: string; action: 'captured' | 'viewed' | 'downloaded' | 'exported' | 'metadata_updated' | 'integrity_verified'; detail?: string }
export interface Evidence {
  id: string; orgId: string; caseId: string; name: string; type: string; source: string; capturedAt: string; capturedBy: string; sha256: string; size: number;
  objectKey: string; metadata: Record<string, unknown>; custody: CustodyEntry[]; modifications: Array<{ at: string; actor: string; before: Record<string, unknown>; after: Record<string, unknown> }>;
}

// ───────── SOAR ─────────
export type AutomationMode = 'OBSERVE' | 'ASSISTED' | 'AUTOMATED';
export type TriggerType = 'signal' | 'vulnerability' | 'exposure' | 'identity';
export interface Condition { field: string; op: 'eq' | 'neq' | 'gte' | 'lte' | 'in' | 'contains' | 'exists'; value?: unknown }
export type PlaybookActionType = 'create_case' | 'create_ticket' | 'notify' | 'tag' | 'propose_account_lock' | 'propose_session_revoke' | 'propose_endpoint_isolation' | 'propose_config_fix' | 'propose_patch_request' | 'propose_permission_change';
export interface PlaybookAction { type: PlaybookActionType; params: Record<string, unknown> }
export interface Playbook {
  id: string; orgId: string; key: string; name: string; description: string; version: number; trigger: { type: TriggerType; kind?: string }; conditions: Condition[];
  actions: PlaybookAction[]; owner: string; riskLevel: 'low' | 'medium' | 'high'; mode: AutomationMode; enabled: boolean; createdAt: string; createdBy: string;
}
export interface RunStep { index: number; action: PlaybookActionType; params: Record<string, unknown>; risky: boolean; status: 'planned' | 'proposed' | 'awaiting_approval' | 'approved' | 'executed' | 'skipped' | 'failed' | 'rejected'; result?: Record<string, unknown>; idempotencyKey: string; planHash?: string; approvalId?: string }
export interface PlaybookRun {
  id: string; orgId: string; playbookId: string; playbookKey: string; playbookVersion: number; mode: AutomationMode; effectiveMode: AutomationMode; trigger: { type: TriggerType; refId: string };
  evidence: string[]; steps: RunStep[]; status: 'observed' | 'awaiting_approval' | 'executing' | 'completed' | 'failed' | 'rejected' | 'stopped' | 'skipped'; reason?: string; createdAt: string; updatedAt: string; history: Array<{ at: string; text: string }>;
}
/** Effect recorded by the lab executor (the only executor shipped): proves the path end-to-end without touching real systems. */
export interface LabEffect { id: string; orgId: string; runId: string; action: PlaybookActionType; target: string; at: string; params: Record<string, unknown> }
export interface Ticket { id: string; orgId: string; title: string; body: string; severity: Severity; status: 'open' | 'closed'; ref?: string; createdAt: string; source: string }

// ───────── notifications ─────────
export interface NotificationChannel {
  id: string; orgId: string; kind: 'email' | 'slack' | 'teams'; name: string; targetEnc?: string; recipients: string[]; minSeverity: Severity; events: string[];
  groupWindowSec: number; mutedUntil?: string; escalation?: { afterSec: number; channelId: string }; enabled: boolean; createdAt: string;
}
export interface NotificationLog {
  id: string; orgId: string; channelId: string; event: string; dedupKey: string; status: 'delivered' | 'failed' | 'suppressed'; reason?: string; providerResponse?: string; error?: string; subject: string; at: string; attempts: number; escalatedFrom?: string;
}

// ───────── connectors ─────────
export type ConnectorKind = 'wazuh' | 'crowdstrike' | 'defender' | 'aws' | 'azure' | 'gcp' | 'entra' | 'okta' | 'google_workspace' | 'ad';
export interface ConnectorConfig {
  id: string; orgId: string; kind: ConnectorKind; name: string; enabled: boolean; baseUrl: string; credentialsEnc?: string; options: Record<string, unknown>;
  permissions: string[]; status: 'not_configured' | 'configured' | 'connected' | 'syncing' | 'error' | 'disabled'; lastTestAt?: string; lastTestOk?: boolean; lastSyncAt?: string;
  lastError?: string; credentialsExpireAt?: string; cursor?: string; createdAt: string; activity: Array<{ at: string; text: string }>;
}
export interface ConnectorRun { id: string; orgId: string; connectorId: string; startedAt: string; finishedAt?: string; status: 'running' | 'ok' | 'error'; counts: Record<string, number>; error?: string }

// ───────── reports ─────────
export type ReportKind = 'executive' | 'technical' | 'incident' | 'identity';
export interface Report { id: string; orgId: string; kind: ReportKind; generatedAt: string; generatedBy: string; periodFrom: string; periodTo: string; sha256: string; size: number; objectKey: string; parameters: Record<string, unknown> }
