import { Injectable } from '@nestjs/common';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { stableStringify } from '../common/ids';
import { ApprovalProof } from '../workflow/ports';
import { SecOpsApproval } from '../store/models';

/** HMAC "digital signature" binding an analyst's decision to one exact plan hash. Swap for KMS/asymmetric signing in prod. */
@Injectable()
export class ApprovalSigner {
  private key: Buffer;
  constructor() {
    const key = process.env.APPROVAL_SIGNING_KEY;
    if (!key && process.env.NODE_ENV === 'production') throw new Error('APPROVAL_SIGNING_KEY is required in production');
    this.key = key ? Buffer.from(key) : randomBytes(32);
  }
  private mac(f: { approvalId: string; planId: string; planHash: string; decision: string; decidedBy: string; decidedAt: string }) {
    return createHmac('sha256', this.key).update(stableStringify(f)).digest('hex');
  }
  sign(a: { id: string; planId: string; planHash: string }, decision: 'approved' | 'rejected', decidedBy: string, decidedAt: string) {
    return this.mac({ approvalId: a.id, planId: a.planId, planHash: a.planHash, decision, decidedBy, decidedAt });
  }
  verifyApproval(a: SecOpsApproval): boolean {
    if (a.status !== 'approved' || !a.signature || !a.decidedBy || !a.decidedAt) return false;
    return this.eq(a.signature, this.sign(a, 'approved', a.decidedBy, a.decidedAt));
  }
  toProof(a: SecOpsApproval): ApprovalProof {
    return { approvalId: a.id, planId: a.planId, planHash: a.planHash, decidedBy: a.decidedBy!, decidedAt: a.decidedAt!, signature: a.signature! };
  }
  /** Used by infra/secret adapters: refuses anything that is not a genuine approved signature. */
  assertProof(p: ApprovalProof | undefined): void {
    const ok = !!p && this.eq(p.signature ?? '', this.mac({ approvalId: p.approvalId, planId: p.planId, planHash: p.planHash, decision: 'approved', decidedBy: p.decidedBy, decidedAt: p.decidedAt }));
    if (!ok) throw new Error('destructive action refused: missing or invalid SecOps approval proof');
  }
  private eq(a: string, b: string) { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); }
}
