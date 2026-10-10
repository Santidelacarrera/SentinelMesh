import { Injectable } from '@nestjs/common';
import { Collection } from './store';
import * as M from './models';

@Injectable()
export class Db {
  scans = new Collection<M.VulnerabilityScan>();
  assets = new Collection<M.AssetContext>();
  findings = new Collection<M.Finding>();
  credentials = new Collection<M.CredentialRecord>();
  identityAudits = new Collection<M.IdentityAudit>();
  policies = new Collection<M.AccessPolicy>();
  anomalies = new Collection<M.TrafficAnomaly>();
  incidents = new Collection<M.SecurityIncident>();
  snapshots = new Collection<M.ForensicSnapshot>();
  plans = new Collection<M.DryRunPlan>();
  workflows = new Collection<M.SecurityWorkflow>();
  executions = new Collection<M.WorkflowExecution>();
  approvals = new Collection<M.SecOpsApproval>();
}
