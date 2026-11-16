import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { CustodyEntry, Evidence } from '../store/enterprise.models';
import { AuditTrail } from '../audit/audit-trail';
import { OBJECT_STORAGE, ObjectStorage } from '../storage/object-storage';
import { newId, now, sha256 } from '../common/ids';
import { Principal } from '../auth/auth';
import { CasesService } from './cases.service';

const MAX_BYTES = 5 * 1024 * 1024;
export const EvidenceSchema = z.object({
  name: z.string().min(1).max(200), type: z.enum(['log', 'memory_dump', 'disk_image', 'network_capture', 'screenshot', 'document', 'config', 'other']).default('other'), source: z.string().min(1).max(200),
  /** base64 for binary, plain text otherwise */ content: z.string().min(1).max(8 * 1024 * 1024), encoding: z.enum(['utf8', 'base64']).default('utf8'), metadata: z.record(z.string(), z.unknown()).default({}),
}).strict();
type Actor = Pick<Principal, 'orgId' | 'userId'>;

/**
 * Forensic evidence with a chain of custody. The original bytes are written once to object storage (never overwritten, no delete API);
 * the SHA-256 is recorded at capture and re-checked on every read/export; every access appends a custody entry; metadata edits keep before/after.
 * Whether any of this is legally admissible is a legal question this software cannot answer.
 */
@Injectable()
export class EvidenceService {
  constructor(private db: Db, private audit: AuditTrail, @Inject(OBJECT_STORAGE) private storage: ObjectStorage, private cases: CasesService) {}
  private custody(me: Actor, action: CustodyEntry['action'], detail?: string): CustodyEntry { return { at: now(), actor: me.userId, action, detail }; }

  async add(me: Actor, caseId: string, i: z.infer<typeof EvidenceSchema>) {
    await this.cases.get(me.orgId, caseId);
    const bytes = i.encoding === 'base64' ? Buffer.from(i.content, 'base64') : Buffer.from(i.content, 'utf8');
    if (!bytes.length) throw new BadRequestException('empty evidence');
    if (bytes.length > MAX_BYTES) throw new BadRequestException(`evidence larger than ${MAX_BYTES} bytes: store it externally and attach a manifest`);
    const id = newId('evd'), objectKey = `evidence/${me.orgId}/${caseId}/${id}`;
    if (await this.storage.get(objectKey)) throw new ConflictException('evidence object already exists (write-once)');
    await this.storage.put(objectKey, bytes);
    const e: Evidence = { id, orgId: me.orgId, caseId, name: i.name, type: i.type, source: i.source, capturedAt: now(), capturedBy: me.userId, sha256: sha256(bytes), size: bytes.length, objectKey, metadata: i.metadata, custody: [this.custody(me, 'captured', `sha256=${sha256(bytes)}`)], modifications: [] };
    await this.db.evidence.put(e);
    await this.db.cases.update(me.orgId, caseId, (r) => { r.evidenceIds.push(id); });
    await this.cases.addTimeline(me.orgId, caseId, me.userId, 'evidence', `evidence "${i.name}" captured (sha256 ${e.sha256.slice(0, 12)}…)`);
    await this.audit.append(me.orgId, me.userId, 'evidence.captured', { evidenceId: id, caseId, sha256: e.sha256, size: e.size, type: i.type });
    return this.meta(e);
  }
  private meta(e: Evidence) { const { objectKey: _internal, ...rest } = e; return rest; }
  async list(orgId: string, caseId: string) { return (await this.db.evidence.where(orgId, { caseId })).map((e) => ({ id: e.id, name: e.name, type: e.type, source: e.source, sha256: e.sha256, size: e.size, capturedAt: e.capturedAt, capturedBy: e.capturedBy })); }
  private async load(orgId: string, id: string) { const e = await this.db.evidence.get(orgId, id); if (!e) throw new NotFoundException('evidence not found'); return e; }

  /** Metadata + custody log. Viewing is itself recorded. */
  async view(me: Actor, id: string) {
    const e = await this.load(me.orgId, id);
    const out = await this.db.evidence.update(me.orgId, id, (r) => { r.custody.push(this.custody(me, 'viewed')); });
    await this.audit.append(me.orgId, me.userId, 'evidence.viewed', { evidenceId: id });
    return this.meta(out ?? e);
  }
  private async readVerified(me: Actor, e: Evidence) {
    const bytes = await this.storage.get(e.objectKey);
    const ok = !!bytes && sha256(bytes) === e.sha256;
    await this.db.evidence.update(me.orgId, e.id, (r) => { r.custody.push(this.custody(me, 'integrity_verified', ok ? 'match' : 'MISMATCH')); });
    if (!ok) { await this.audit.append(me.orgId, me.userId, 'evidence.integrity_failure', { evidenceId: e.id, expected: e.sha256 }); throw new ConflictException('evidence integrity check FAILED: the stored bytes no longer match the SHA-256 recorded at capture'); }
    return bytes!;
  }
  async verify(me: Actor, id: string) {
    const e = await this.load(me.orgId, id);
    try { await this.readVerified(me, e); return { evidenceId: id, intact: true, sha256: e.sha256 }; } catch (x) { if (x instanceof ConflictException) return { evidenceId: id, intact: false, expectedSha256: e.sha256 }; throw x; }
  }
  async download(me: Actor, id: string) {
    const e = await this.load(me.orgId, id), bytes = await this.readVerified(me, e);
    await this.db.evidence.update(me.orgId, id, (r) => { r.custody.push(this.custody(me, 'downloaded')); });
    await this.audit.append(me.orgId, me.userId, 'evidence.downloaded', { evidenceId: id, sha256: e.sha256 });
    return { name: e.name, type: e.type, sha256: e.sha256, bytes };
  }
  /** Only descriptive metadata can change; the content reference and hash are immutable (also enforced by a database trigger). */
  async updateMetadata(me: Actor, id: string, patch: Record<string, unknown>, reason: string) {
    if (reason.length < 5) throw new BadRequestException('a reason is required to change evidence metadata');
    const e = await this.load(me.orgId, id);
    const out = await this.db.evidence.update(me.orgId, id, (r) => { const before = { ...r.metadata }; r.metadata = { ...r.metadata, ...patch }; r.modifications.push({ at: now(), actor: me.userId, before, after: { ...r.metadata } }); r.custody.push(this.custody(me, 'metadata_updated', reason)); });
    await this.audit.append(me.orgId, me.userId, 'evidence.metadata_updated', { evidenceId: id, keys: Object.keys(patch), reason, sha256: e.sha256 });
    return this.meta(out);
  }
  /** Investigation export: manifest with hashes + contents + full custody history. Every item is verified before it leaves; the export is recorded. */
  async exportCase(me: Actor, caseId: string, purpose: string) {
    if (purpose.length < 5) throw new BadRequestException('state the purpose of the export (at least 5 characters)');
    const c = await this.cases.get(me.orgId, caseId), items = await this.db.evidence.where(me.orgId, { caseId });
    const files: Array<Record<string, unknown>> = [];
    for (const e of items) {
      const bytes = await this.readVerified(me, e);
      await this.db.evidence.update(me.orgId, e.id, (r) => { r.custody.push(this.custody(me, 'exported', purpose)); });
      files.push({ id: e.id, name: e.name, type: e.type, source: e.source, sha256: e.sha256, size: e.size, capturedAt: e.capturedAt, capturedBy: e.capturedBy, metadata: e.metadata, contentBase64: bytes.toString('base64'), custody: (await this.db.evidence.get(me.orgId, e.id))!.custody, modifications: e.modifications });
    }
    const manifest = { exportedAt: now(), exportedBy: me.userId, purpose, case: { id: c.id, number: c.number, name: c.name }, files: files.map((f) => ({ id: f['id'], name: f['name'], sha256: f['sha256'], size: f['size'] })) };
    await this.cases.addTimeline(me.orgId, caseId, me.userId, 'evidence', `evidence exported (${files.length} item(s)): ${purpose}`);
    await this.audit.append(me.orgId, me.userId, 'evidence.exported', { caseId, items: files.length, purpose, manifestSha256: sha256(JSON.stringify(manifest)) });
    return { manifest, manifestSha256: sha256(JSON.stringify(manifest)), files, notice: 'This export is a technical record. Legal admissibility has not been assessed.' };
  }
}
