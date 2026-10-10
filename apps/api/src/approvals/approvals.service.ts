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
  request(orgId: string, executionId: string, stepName: string, plan: { id: string; planHash: string }): SecOpsApproval {
    const existing = this.db.approvals.list(orgId, (a) => a.executionId === executionId && a.stepName === stepName)[0];
    if (existing) return existing;
    const a = this.db.approvals.put({ id: newId('apr'), orgId, executionId, stepName, planId: plan.id, planHash: plan.planHash, status: 'pending', requestedAt: now() });
    this.audit.append(orgId, 'system', 'approval.requested', { approvalId: a.id, executionId, stepName, planId: plan.id, planHash: plan.planHash });
    return a;
  }

  find(orgId: string, executionId: string, stepName: string) {
    return this.db.approvals.list(orgId, (a) => a.executionId === executionId && a.stepName === stepName)[0];
  }

  list(orgId: string, status?: string) { return this.db.approvals.list(orgId, (a) => !status || a.status === status); }

  async decide(me: Principal, id: string, decision: 'approved' | 'rejected', comment?: string): Promise<SecOpsApproval> {
    const a = this.db.approvals.get(me.orgId, id);
    if (!a) throw new NotFoundException('approval not found'); // also hides other tenants' ids
    if (a.status !== 'pending') throw new ConflictException(`already ${a.status}`);
    const ex = this.db.executions.get(me.orgId, a.executionId);
    if (ex && ex.context['requestedBy'] === me.userId) throw new ForbiddenException('separation of duties: the requester cannot approve their own change');
    const decidedAt = now();
    const signature = this.signer.sign(a, decision, me.userId, decidedAt);
    const out = this.db.approvals.update(me.orgId, id, { status: decision, decidedBy: me.userId, decidedAt, comment, signature });
    this.audit.append(me.orgId, me.userId, `approval.${decision}`, { approvalId: id, executionId: a.executionId, planId: a.planId, planHash: a.planHash, comment });
    await this.queue.enqueue({ orgId: me.orgId, executionId: a.executionId });
    return out;
  }
}
