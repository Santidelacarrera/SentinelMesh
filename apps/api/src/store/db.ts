import { Injectable } from '@nestjs/common';
import { MemoryRepo, Repo } from './store';
import * as M from './models';
import * as E from './enterprise.models';

/** Repositories. Memory by default; `PgRepos` (DATABASE_URL) swaps in PostgreSQL-backed ones (see store/pg.ts). */
@Injectable()
export class Db {
  scans: Repo<M.VulnerabilityScan> = new MemoryRepo();
  assets: Repo<M.AssetContext> = new MemoryRepo();
  findings: Repo<M.Finding> = new MemoryRepo();
  credentials: Repo<M.CredentialRecord> = new MemoryRepo();
  identityAudits: Repo<M.IdentityAudit> = new MemoryRepo();
  policies: Repo<M.AccessPolicy> = new MemoryRepo();
  anomalies: Repo<M.TrafficAnomaly> = new MemoryRepo();
  incidents: Repo<M.SecurityIncident> = new MemoryRepo();
  snapshots: Repo<M.ForensicSnapshot> = new MemoryRepo();
  plans: Repo<M.DryRunPlan> = new MemoryRepo();
  workflows: Repo<M.SecurityWorkflow> = new MemoryRepo();
  executions: Repo<M.WorkflowExecution> = new MemoryRepo();
  approvals: Repo<M.SecOpsApproval> = new MemoryRepo();
  // enterprise domain (db/migrations/0002_enterprise.sql)
  orgs: Repo<E.OrgProfile> = new MemoryRepo();
  users: Repo<E.UserAccount> = new MemoryRepo();
  sessions: Repo<E.Session> = new MemoryRepo();
  roles: Repo<E.CustomRole> = new MemoryRepo();
  resets: Repo<E.PasswordReset> = new MemoryRepo();
  settings: Repo<E.Setting> = new MemoryRepo();
  inventory: Repo<E.InventoryAsset> = new MemoryRepo();
  relations: Repo<E.Relation> = new MemoryRepo();
  vulns: Repo<E.Vulnerability> = new MemoryRepo();
  intel: Repo<E.IntelRecord> = new MemoryRepo();
  exposures: Repo<E.ExposureFinding> = new MemoryRepo();
  exposureEvents: Repo<E.ExposureEvent> = new MemoryRepo();
  identities: Repo<E.Identity> = new MemoryRepo();
  identityChanges: Repo<E.IdentityChange> = new MemoryRepo();
  signals: Repo<E.Signal> = new MemoryRepo();
  correlations: Repo<E.Correlation> = new MemoryRepo();
  cases: Repo<E.Case> = new MemoryRepo();
  evidence: Repo<E.Evidence> = new MemoryRepo();
  playbooks: Repo<E.Playbook> = new MemoryRepo();
  runs: Repo<E.PlaybookRun> = new MemoryRepo();
  labEffects: Repo<E.LabEffect> = new MemoryRepo();
  tickets: Repo<E.Ticket> = new MemoryRepo();
  channels: Repo<E.NotificationChannel> = new MemoryRepo();
  notifications: Repo<E.NotificationLog> = new MemoryRepo();
  connectors: Repo<E.ConnectorConfig> = new MemoryRepo();
  connectorRuns: Repo<E.ConnectorRun> = new MemoryRepo();
  reports: Repo<E.Report> = new MemoryRepo();
}

export const TABLES: Record<keyof Db, string> = {
  scans: 'vulnerability_scan', assets: 'asset_context', findings: 'finding', credentials: 'credential_record', identityAudits: 'identity_audit',
  policies: 'access_policy', anomalies: 'traffic_anomaly', incidents: 'security_incident', snapshots: 'forensic_snapshot', plans: 'dry_run_plan',
  workflows: 'security_workflow', executions: 'workflow_execution', approvals: 'secops_approval',
  orgs: 'org_profile', users: 'user_account', sessions: 'auth_session', roles: 'custom_role', resets: 'password_reset', settings: 'org_setting',
  inventory: 'inventory_asset', relations: 'asset_relation', vulns: 'vulnerability', intel: 'intel_record', exposures: 'exposure_finding', exposureEvents: 'exposure_event',
  identities: 'identity', identityChanges: 'identity_change', signals: 'signal', correlations: 'correlation', cases: 'security_case', evidence: 'evidence_item',
  playbooks: 'playbook', runs: 'playbook_run', labEffects: 'lab_effect', tickets: 'ticket', channels: 'notification_channel', notifications: 'notification_log',
  connectors: 'connector', connectorRuns: 'connector_run', reports: 'report',
};
