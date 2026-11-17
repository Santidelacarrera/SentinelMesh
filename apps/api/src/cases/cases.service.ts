import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { Case, CaseStatus, TimelineEntry } from '../store/enterprise.models';
import type { Severity } from '../store/models';
import { AuditTrail } from '../audit/audit-trail';
import { newId, now } from '../common/ids';
import { redactString } from '../common/mask';
import { Principal } from '../auth/auth';

export const CaseSchema = z.object({
  name: z.string().min(1).max(200), description: z.string().max(5000).default(''), severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  assetIds: z.array(z.string()).max(200).default([]), identityIds: z.array(z.string()).max(200).default([]), vulnerabilityIds: z.array(z.string()).max(200).default([]), signalIds: z.array(z.string()).max(500).default([]),
  recommendations: z.array(z.string().max(500)).max(30).default([]),
}).strict();
export const TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  new: ['investigating', 'closed'], investigating: ['contained', 'remediating', 'resolved', 'closed'], contained: ['investigating', 'remediating', 'resolved'],
  remediating: ['investigating', 'contained', 'resolved'], resolved: ['closed', 'investigating'], closed: [],
};
type Actor = Pick<Principal, 'orgId' | 'userId'>;

@Injectable()
export class CasesService {
  constructor(private db: Db, private audit: AuditTrail) {}

  private entry(actor: string, kind: TimelineEntry['kind'], text: string, data?: unknown): TimelineEntry { return { id: newId('tl'), at: now(), actor, kind, text: redactString(text).slice(0, 2000), data }; }

  /** Cases are numbered per organisation; the unique (org, number) index decides races between replicas, so we retry with the next number. */
  async open(me: Actor, i: z.infer<typeof CaseSchema>, source: Case['source'] = 'manual', extra: Partial<Case> = {}): Promise<Case> {
    await this.assertLinks(me.orgId, i);
    for (let attempt = 0; attempt < 8; attempt++) {
      const number = (await this.db.cases.list(me.orgId)).reduce((m, c) => Math.max(m, c.number), 0) + 1;
      const c: Case = { id: newId('case'), orgId: me.orgId, number, name: i.name, description: i.description, severity: i.severity, status: 'new', assetIds: i.assetIds, identityIds: i.identityIds, vulnerabilityIds: i.vulnerabilityIds, signalIds: i.signalIds, evidenceIds: [],
        recommendations: i.recommendations, actions: [], timeline: [this.entry(me.userId, 'opened', `Case opened (${source})`)], source, openedAt: now(), createdBy: me.userId, ...extra };
      const { row, created } = await this.db.cases.createUnique(c, { number });
      if (!created) continue;
      await this.audit.append(me.orgId, me.userId, 'case.opened', { caseId: row.id, number, severity: row.severity, source });
      return row;
    }
    throw new ConflictException('could not allocate a case number, retry');
  }
  private async assertLinks(orgId: string, i: { assetIds: string[]; identityIds: string[]; vulnerabilityIds: string[] }) {
    const check = async (ids: string[], repo: { get(o: string, id: string): Promise<unknown> }, what: string) => { for (const id of ids) if (!(await repo.get(orgId, id))) throw new BadRequestException(`${what} ${id} not found`); };
    await check(i.assetIds, this.db.inventory, 'asset'); await check(i.identityIds, this.db.identities, 'identity'); await check(i.vulnerabilityIds, this.db.vulns, 'vulnerability');
  }
  async get(orgId: string, id: string) { const c = await this.db.cases.get(orgId, id); if (!c) throw new NotFoundException('case not found'); return c; }
  async detail(orgId: string, id: string) {
    const c = await this.get(orgId, id);
    const [assets, identities, vulns, signals, evidence] = await Promise.all([Promise.all(c.assetIds.map((x) => this.db.inventory.get(orgId, x))), Promise.all(c.identityIds.map((x) => this.db.identities.get(orgId, x))), Promise.all(c.vulnerabilityIds.map((x) => this.db.vulns.get(orgId, x))), Promise.all(c.signalIds.slice(0, 100).map((x) => this.db.signals.get(orgId, x))), Promise.all(c.evidenceIds.map((x) => this.db.evidence.get(orgId, x)))]);
    const correlation = c.correlationId ? await this.db.correlations.get(orgId, c.correlationId) : undefined;
    return { case: c, assets: assets.filter(Boolean), identities: identities.filter(Boolean), vulnerabilities: vulns.filter(Boolean), signals: signals.filter(Boolean), evidence: evidence.filter(Boolean).map((e) => ({ id: e!.id, name: e!.name, type: e!.type, source: e!.source, sha256: e!.sha256, size: e!.size, capturedAt: e!.capturedAt, capturedBy: e!.capturedBy })), correlation };
  }
  async list(orgId: string, q: Record<string, string | undefined>) {
    const text = q.q?.toLowerCase();
    const all = (await this.db.cases.list(orgId, (c) => (!q.status || q.status.split(',').includes(c.status)) && (!q.severity || q.severity.split(',').includes(c.severity)) && (!q.assignee || c.assigneeId === q.assignee) && (!text || `${c.name} #${c.number}`.toLowerCase().includes(text)))).sort((a, b) => b.openedAt.localeCompare(a.openedAt));
    const limit = Math.min(Number(q.limit ?? 50) || 50, 200), offset = Math.max(Number(q.offset ?? 0) || 0, 0);
    return { total: all.length, items: all.slice(offset, offset + limit).map(({ timeline, ...c }) => ({ ...c, timelineLength: timeline.length })) };
  }
  async setStatus(me: Actor, id: string, to: CaseStatus, note?: string) {
    const c = await this.get(me.orgId, id);
    if (!TRANSITIONS[c.status].includes(to)) throw new BadRequestException(`cannot move a case from ${c.status} to ${to} (allowed: ${TRANSITIONS[c.status].join(', ') || 'none'})`);
    if ((to === 'closed' || to === 'resolved') && (!note || note.length < 5)) throw new BadRequestException(`${to === 'closed' ? 'closing' : 'resolving'} a case requires a note`);
    const out = await this.db.cases.update(me.orgId, id, (r) => {
      if (!TRANSITIONS[r.status].includes(to)) throw new ConflictException('case changed concurrently');
      r.timeline.push(this.entry(me.userId, 'status', `${r.status} → ${to}${note ? `: ${note}` : ''}`)); r.status = to; if (to === 'closed') r.closedAt = now();
    });
    await this.audit.append(me.orgId, me.userId, 'case.status_changed', { caseId: id, from: c.status, to, note });
    return out;
  }
  async assign(me: Actor, id: string, assigneeId: string | null) {
    if (assigneeId && !(await this.db.users.get(me.orgId, assigneeId))) throw new BadRequestException('assignee is not a user of this organisation');
    const out = await this.db.cases.update(me.orgId, id, (r) => { r.assigneeId = assigneeId ?? undefined; r.timeline.push(this.entry(me.userId, 'assigned', assigneeId ? `assigned to ${assigneeId}` : 'unassigned')); });
    await this.audit.append(me.orgId, me.userId, 'case.assigned', { caseId: id, assigneeId });
    return out;
  }
  async comment(me: Actor, id: string, text: string) {
    const out = await this.db.cases.update(me.orgId, id, (r) => { r.timeline.push(this.entry(me.userId, 'comment', text)); });
    await this.audit.append(me.orgId, me.userId, 'case.commented', { caseId: id });
    return out.timeline.at(-1);
  }
  async link(me: Actor, id: string, l: { assetIds?: string[]; identityIds?: string[]; vulnerabilityIds?: string[]; signalIds?: string[] }) {
    await this.assertLinks(me.orgId, { assetIds: l.assetIds ?? [], identityIds: l.identityIds ?? [], vulnerabilityIds: l.vulnerabilityIds ?? [] });
    const out = await this.db.cases.update(me.orgId, id, (r) => {
      const merge = (a: string[], b?: string[]) => [...new Set([...a, ...(b ?? [])])];
      r.assetIds = merge(r.assetIds, l.assetIds); r.identityIds = merge(r.identityIds, l.identityIds); r.vulnerabilityIds = merge(r.vulnerabilityIds, l.vulnerabilityIds); r.signalIds = merge(r.signalIds, l.signalIds);
      r.timeline.push(this.entry(me.userId, 'link', `linked ${Object.entries(l).map(([k, v]) => `${v?.length ?? 0} ${k.replace('Ids', '')}`).join(', ')}`));
    });
    return out;
  }
  /** Records something that was done (by a person or a playbook). Recommendations stay separate from actions actually performed. */
  async recordAction(actor: string, orgId: string, id: string, action: string, result: string) {
    return this.db.cases.update(orgId, id, (r) => { r.actions.push({ at: now(), actor, action, result }); r.timeline.push(this.entry(actor, 'action', `${action}: ${result}`)); });
  }
  async addTimeline(orgId: string, id: string, actor: string, kind: TimelineEntry['kind'], text: string, data?: unknown) {
    return this.db.cases.update(orgId, id, (r) => { r.timeline.push(this.entry(actor, kind, text, data)); });
  }
  async timeline(orgId: string, id: string) { return (await this.get(orgId, id)).timeline.slice().sort((a, b) => a.at.localeCompare(b.at)); }
  static severityMax(a: Severity, b: Severity): Severity { const o: Severity[] = ['info', 'low', 'medium', 'high', 'critical']; return o.indexOf(a) >= o.indexOf(b) ? a : b; }
}
