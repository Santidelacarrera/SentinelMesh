import { ForbiddenException, Inject, Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { Db } from '../store/db';
import { SecOpsApproval } from '../store/models';
import { ApprovalSigner } from './signer';
import { AuditTrail } from '../audit/audit-trail';
import { newId, now } from '../common/ids';
import { JOB_QUEUE, JobQueue } from '../queue/queue';
import { Principal } from '../auth/auth';

@Injectable()
export class ApprovalsService {
  constructor(private db: Db, private signer: ApprovalSigner, private audit: AuditTrail, @Inject(JOB_QUEUE) private queue: JobQueue) {}

  /** Idempotent: one approval request per (execution, step). */
  async request(orgId: string, executionId: string, stepName: string, plan: { id: string; planHash: string }): Promise<SecOpsApproval> {
    // The DB unique index on (execution, step) makes this safe even if two replicas ask at the same moment.
    const { row, created } = await this.db.approvals.createUnique(
      { id: newId('apr'), orgId, executionId, stepName, planId: plan.id, planHash: plan.planHash, status: 'pending', requestedAt: now() }, { executionId, stepName });
    if (created) await this.audit.append(orgId, 'system', 'approval.requested', { approvalId: row.id, executionId, stepName, planId: plan.id, planHash: plan.planHash });
    return row;
  }

  async find(orgId: string, executionId: string, stepName: string) {
    return (await this.db.approvals.where(orgId, { executionId, stepName }))[0];
  }

  list(orgId: string, status?: string) { return status ? this.db.approvals.where(orgId, { status }) : this.db.approvals.list(orgId); }

  async decide(me: Principal, id: string, decision: 'approved' | 'rejected', comment?: string): Promise<SecOpsApproval> {
    const a = await this.db.approvals.get(me.orgId, id);
    if (!a) throw new NotFoundException('approval not found'); // also hides other tenants' ids
    if (a.status !== 'pending') throw new ConflictException(`already ${a.status}`);
    const ex = await this.db.executions.get(me.orgId, a.executionId);
    if (ex && ex.context['requestedBy'] === me.userId) throw new ForbiddenException('separation of duties: the requester cannot approve their own change');
    const decidedAt = now();
    const signature = await this.signer.sign(a, decision, me.userId, decidedAt);
    // Compare-and-set under a row lock: if two approvers (on two replicas) decide at once, exactly one wins, the other gets 409.
    const out = await this.db.approvals.update(me.orgId, id, (r) => {
      if (r.status !== 'pending') throw new ConflictException(`already ${r.status}`);
      Object.assign(r, { status: decision, decidedBy: me.userId, decidedAt, comment, signature });
    });
    await this.audit.append(me.orgId, me.userId, `approval.${decision}`, { approvalId: id, executionId: a.executionId, planId: a.planId, planHash: a.planHash, comment });
    await this.queue.enqueue({ orgId: me.orgId, executionId: a.executionId });
    return out;
  }
}
