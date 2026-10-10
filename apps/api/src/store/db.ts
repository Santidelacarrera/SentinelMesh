import { Injectable } from '@nestjs/common';
import { MemoryRepo, Repo } from './store';
import * as M from './models';

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
}

export const TABLES: Record<keyof Db, string> = {
  scans: 'vulnerability_scan', assets: 'asset_context', findings: 'finding', credentials: 'credential_record', identityAudits: 'identity_audit',
  policies: 'access_policy', anomalies: 'traffic_anomaly', incidents: 'security_incident', snapshots: 'forensic_snapshot', plans: 'dry_run_plan',
  workflows: 'security_workflow', executions: 'workflow_execution', approvals: 'secops_approval',
};
