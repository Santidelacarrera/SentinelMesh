import { Injectable } from '@nestjs/common';
import { createHmac, createPrivateKey, createPublicKey, KeyObject, randomBytes, sign as edSign, timingSafeEqual, verify as edVerify } from 'node:crypto';
import { KMSClient, SignCommand, VerifyCommand } from '@aws-sdk/client-kms';
import { stableStringify } from '../common/ids';
import { ApprovalProof } from '../workflow/ports';
import { SecOpsApproval } from '../store/models';

/** A signature backend: symmetric HMAC (dev), Ed25519 key pair, or AWS KMS (asymmetric, key never leaves the HSM). */
export interface SignatureBackend { readonly name: string; sign(msg: Buffer): Promise<string>; verify(msg: Buffer, sig: string): Promise<boolean> }

export class HmacBackend implements SignatureBackend {
  readonly name = 'hmac-sha256';
  constructor(private key: Buffer) {}
  async sign(msg: Buffer) { return createHmac('sha256', this.key).update(msg).digest('hex'); }
  async verify(msg: Buffer, sig: string) { const a = Buffer.from(sig), b = Buffer.from(await this.sign(msg)); return a.length === b.length && timingSafeEqual(a, b); }
}

/** Ed25519: only holders of the private key can sign; verification needs just the public key (can live on other services). */
export class Ed25519Backend implements SignatureBackend {
  readonly name = 'ed25519';
  private priv?: KeyObject; private pub: KeyObject;
  constructor(privatePem?: string, publicPem?: string) {
    if (privatePem) { this.priv = createPrivateKey(privatePem); this.pub = createPublicKey(this.priv); }
    else if (publicPem) this.pub = createPublicKey(publicPem);
    else throw new Error('Ed25519Backend needs a private or public key');
  }
  async sign(msg: Buffer) { if (!this.priv) throw new Error('no private key: this instance can only verify'); return edSign(null, msg, this.priv).toString('hex'); }
  async verify(msg: Buffer, sig: string) { try { return edVerify(null, msg, this.pub, Buffer.from(sig, 'hex')); } catch { return false; } }
}

export class KmsBackend implements SignatureBackend {
  readonly name = 'aws-kms-ecdsa-sha256';
  constructor(private kms: KMSClient, private keyId: string) {}
  async sign(msg: Buffer) {
    const r = await this.kms.send(new SignCommand({ KeyId: this.keyId, Message: msg, MessageType: 'RAW', SigningAlgorithm: 'ECDSA_SHA_256' }));
    return Buffer.from(r.Signature!).toString('hex');
  }
  async verify(msg: Buffer, sig: string) {
    try { return !!(await this.kms.send(new VerifyCommand({ KeyId: this.keyId, Message: msg, MessageType: 'RAW', Signature: Buffer.from(sig, 'hex'), SigningAlgorithm: 'ECDSA_SHA_256' }))).SignatureValid; }
    catch { return false; }
  }
}

export function backendFromEnv(env = process.env): SignatureBackend {
  if (env.APPROVAL_KMS_KEY_ID) return new KmsBackend(new KMSClient({ endpoint: env.AWS_ENDPOINT_URL }), env.APPROVAL_KMS_KEY_ID);
  if (env.APPROVAL_ED25519_PRIVATE_KEY) return new Ed25519Backend(env.APPROVAL_ED25519_PRIVATE_KEY.replace(/\\n/g, '\n'));
  if (env.APPROVAL_SIGNING_KEY) return new HmacBackend(Buffer.from(env.APPROVAL_SIGNING_KEY));
  if (env.NODE_ENV === 'production') throw new Error('production requires APPROVAL_KMS_KEY_ID, APPROVAL_ED25519_PRIVATE_KEY or APPROVAL_SIGNING_KEY');
  return new HmacBackend(randomBytes(32));
}

/** Binds an analyst's decision to one exact plan hash. */
@Injectable()
export class ApprovalSigner {
  private backend: SignatureBackend;
  constructor() { this.backend = backendFromEnv(); }
  use(b: SignatureBackend) { this.backend = b; return this; }
  get backendName() { return this.backend.name; }

  private msg(f: { approvalId: string; planId: string; planHash: string; decision: string; decidedBy: string; decidedAt: string }) { return Buffer.from(stableStringify(f)); }
  sign(a: { id: string; planId: string; planHash: string }, decision: 'approved' | 'rejected', decidedBy: string, decidedAt: string) {
    return this.backend.sign(this.msg({ approvalId: a.id, planId: a.planId, planHash: a.planHash, decision, decidedBy, decidedAt }));
  }
  async verifyApproval(a: SecOpsApproval): Promise<boolean> {
    if (a.status !== 'approved' || !a.signature || !a.decidedBy || !a.decidedAt) return false;
    return this.backend.verify(this.msg({ approvalId: a.id, planId: a.planId, planHash: a.planHash, decision: 'approved', decidedBy: a.decidedBy, decidedAt: a.decidedAt }), a.signature);
  }
  toProof(a: SecOpsApproval): ApprovalProof {
    return { approvalId: a.id, planId: a.planId, planHash: a.planHash, decidedBy: a.decidedBy!, decidedAt: a.decidedAt!, signature: a.signature! };
  }
  /** Used by infra/secret adapters: refuses anything that is not a genuine approved signature. */
  async assertProof(p: ApprovalProof | undefined): Promise<void> {
    const ok = !!p && !!p.signature && await this.backend.verify(this.msg({ approvalId: p.approvalId, planId: p.planId, planHash: p.planHash, decision: 'approved', decidedBy: p.decidedBy, decidedAt: p.decidedAt }), p.signature);
    if (!ok) throw new Error('destructive action refused: missing or invalid SecOps approval proof');
  }
}
