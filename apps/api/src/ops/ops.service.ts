import { Inject, Injectable } from '@nestjs/common';
import { Db } from '../store/db';
import { AuditTrail } from '../audit/audit-trail';
import { JOB_QUEUE, JobQueue } from '../queue/queue';

const H = 3600_000;
/** What an operator needs to see to find broken things: failed syncs, stuck approvals/runs/executions, auth errors, failed notifications, queue backlog. Only real data; no synthetic "all green". */
@Injectable()
export class OpsService {
  constructor(private db: Db, private audit: AuditTrail, @Inject(JOB_QUEUE) private queue: JobQueue) {}
  async health(orgId: string) {
    const nowMs = Date.now(), iso = (ms: number) => new Date(nowMs - ms).toISOString();
    const [connectors, runs, execs, notes, entries, depth] = await Promise.all([this.db.connectors.list(orgId), this.db.runs.list(orgId), this.db.executions.list(orgId), this.db.notifications.list(orgId, (n) => n.at >= iso(24 * H)), this.audit.list(orgId), this.queue.depth()]);
    const recent = entries.filter((e) => e.at >= iso(H));
    const issues: Array<{ severity: 'critical' | 'warning'; area: string; detail: string }> = [];
    const failedSyncs = connectors.filter((c) => c.enabled && c.status === 'error');
    for (const c of failedSyncs) issues.push({ severity: 'warning', area: 'connector', detail: `${c.name} (${c.kind}) is failing: ${c.lastError ?? 'unknown error'}` });
    for (const c of connectors.filter((x) => x.enabled && x.lastSyncAt && x.lastSyncAt < iso(24 * H))) issues.push({ severity: 'warning', area: 'connector', detail: `${c.name} has not synchronised for more than 24 h (last ${c.lastSyncAt})` });
    const stuckApprovals = runs.filter((r) => r.status === 'awaiting_approval' && r.updatedAt < iso(24 * H));
    if (stuckApprovals.length) issues.push({ severity: 'warning', area: 'soar', detail: `${stuckApprovals.length} playbook run(s) have waited for approval for more than 24 h` });
    const stuckRuns = runs.filter((r) => r.status === 'executing' && r.updatedAt < iso(H)), stuckExec = execs.filter((e) => e.status === 'running' && e.updatedAt < iso(H));
    if (stuckRuns.length + stuckExec.length) issues.push({ severity: 'critical', area: 'tasks', detail: `${stuckRuns.length + stuckExec.length} task(s) have been "running" for more than 1 h without progress (incomplete)` });
    const authFails = recent.filter((e) => e.event === 'auth.login_failed').length;
    if (authFails >= 20) issues.push({ severity: 'warning', area: 'auth', detail: `${authFails} failed logins in the last hour` });
    const nfail = notes.filter((n) => n.status === 'failed').length;
    if (nfail) issues.push({ severity: 'warning', area: 'notifications', detail: `${nfail} notification(s) failed in the last 24 h` });
    if (depth.failed) issues.push({ severity: 'critical', area: 'queue', detail: `${depth.failed} job(s) exhausted retries and are parked in the queue` });
    if (depth.waiting > 100) issues.push({ severity: 'warning', area: 'queue', detail: `backlog of ${depth.waiting} waiting job(s)` });
    const chain = await this.audit.verify(orgId); if (!chain.ok) issues.push({ severity: 'critical', area: 'audit', detail: `audit chain broken at entry ${chain.brokenAt}` });
    return { status: issues.some((i) => i.severity === 'critical') ? 'critical' : issues.length ? 'degraded' : 'ok', issues, queue: depth, connectors: { total: connectors.length, failing: failedSyncs.length }, authFailuresLastHour: authFails, auditChain: chain, generatedAt: new Date().toISOString() };
  }
}
