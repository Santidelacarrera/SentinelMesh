import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { Db } from '../store/db';
import { AuditTrail } from '../audit/audit-trail';
import { CtemService } from '../ctem/ctem.service';
import { IamService } from '../iam/iam.service';
import { assertSafeUrl } from '../common/ssrf';
import { redact, redactString } from '../common/mask';
import { now, newId } from '../common/ids';
import { Principal } from '../auth/auth';

export type ExplainKind = 'case' | 'vulnerability' | 'attack_path' | 'correlation' | 'identity' | 'priorities';
export interface Explanation {
  kind: ExplainKind; id?: string; generatedAt: string; summary: string; details: string[];
  /** Records the answer was derived from (type + id): nothing in `details` comes from anywhere else. */
  sources: Array<{ type: string; id: string }>; confidence: { level: 'high' | 'medium' | 'low'; value: number; basis: string }; assumptions: string[]; limitations: string[];
  /** Suggestions only. `executed` is always empty: this service cannot run anything. */
  recommendations: string[]; executed: never[];
  externalNarrative?: { text: string; provider: string; notice: string };
}
const lvl = (v: number): 'high' | 'medium' | 'low' => (v >= 0.75 ? 'high' : v >= 0.45 ? 'medium' : 'low');
const CONF = { confirmed: 1, suspected: 0.7, unverified: 0.4 } as const;
/** Pseudonymises emails and IPv4 addresses before anything leaves the platform (token-wise: no backtracking-prone regexes on untrusted text). */
const isEmail = (t: string) => { const at = t.indexOf('@'); return t.length <= 254 && at > 0 && at === t.lastIndexOf('@') && t.slice(at + 1).includes('.'); };
const isIp = (t: string) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(t);
const clean = (s: string) => redactString(s).split(/([\s,;"'<>()[\]{}]+)/).map((t) => (isEmail(t) ? '<EMAIL>' : isIp(t) ? '<IP>' : t)).join('');

/**
 * AI assistant, grounded by construction: the explanation is assembled deterministically from stored records and carries its sources,
 * confidence, assumptions and limits. An optional external language model may ADD a narrative, but only when the operator configured it,
 * an administrator gave consent for the organisation, and only after redaction/pseudonymisation; its text is labelled and never replaces the
 * grounded answer. The assistant has no write path: it cannot change data or run actions.
 */
@Injectable()
export class AiService {
  constructor(private db: Db, private audit: AuditTrail, private ctem: CtemService, private iam: IamService) {}

  async settings(orgId: string) { return { externalEnabled: !!((await this.consent(orgId))?.enabled), providerConfigured: !!process.env.AI_LLM_URL, consent: await this.consent(orgId) }; }
  private async consent(orgId: string) { return (await this.db.settings.where(orgId, { key: 'ai.external' }))[0]?.value as { enabled: boolean; by: string; at: string } | undefined; }
  async setConsent(me: Principal, enabled: boolean) {
    if (enabled && !process.env.AI_LLM_URL) throw new BadRequestException('no external AI provider is configured by the operator (AI_LLM_URL)');
    const ex = (await this.db.settings.where(me.orgId, { key: 'ai.external' }))[0], value = { enabled, by: me.userId, at: now() };
    if (ex) await this.db.settings.update(me.orgId, ex.id, { value, updatedAt: now(), updatedBy: me.userId }); else await this.db.settings.put({ id: newId('set'), orgId: me.orgId, key: 'ai.external', value, updatedAt: now(), updatedBy: me.userId });
    await this.audit.append(me.orgId, me.userId, enabled ? 'ai.external_consent_granted' : 'ai.external_consent_revoked', {});
    return this.settings(me.orgId);
  }

  async explain(me: Principal, kind: ExplainKind, id?: string, external = false): Promise<Explanation> {
    const base = { kind, id, generatedAt: now(), executed: [] as never[] };
    let e: Omit<Explanation, 'generatedAt' | 'kind' | 'id' | 'executed'>;
    switch (kind) {
      case 'vulnerability': e = await this.vuln(me.orgId, id); break;
      case 'case': e = await this.case_(me.orgId, id); break;
      case 'correlation': e = await this.corr(me.orgId, id); break;
      case 'identity': e = await this.ident(me.orgId, id); break;
      case 'attack_path': e = await this.path(me.orgId, id); break;
      case 'priorities': e = await this.prio(me.orgId); break;
    }
    const out: Explanation = { ...base, ...e };
    await this.audit.append(me.orgId, me.userId, 'ai.explained', { kind, id, sources: out.sources.length, external });
    if (external) out.externalNarrative = await this.narrate(me, out);
    return out;
  }
  private need(id?: string) { if (!id) throw new BadRequestException('id is required'); return id; }

  private async vuln(orgId: string, id?: string) {
    const v = await this.db.vulns.get(orgId, this.need(id)); if (!v) throw new NotFoundException('vulnerability not found');
    const a = await this.db.inventory.get(orgId, v.assetId), p = v.priority;
    return { summary: `${v.cve ?? v.title} on ${a?.name ?? 'an unknown asset'} is ${p?.level ?? 'unprioritised'} (${p?.score ?? 'n/a'}/100) and ${v.confidence}.`,
      details: [v.description || 'No description recorded.', ...(p?.factors.filter((f) => f.points !== 0).map((f) => `${f.name}: ${f.points > 0 ? '+' : ''}${f.points} — ${f.detail}`) ?? []), `Status ${v.status}${v.dueDate ? `, due ${v.dueDate.slice(0, 10)}` : ''}; reported by ${v.source}.`],
      sources: [{ type: 'vulnerability', id: v.id }, ...(a ? [{ type: 'asset', id: a.id }] : [])], confidence: { value: CONF[v.confidence], level: lvl(CONF[v.confidence]), basis: `detection confidence is "${v.confidence}"` },
      assumptions: ['The asset context (criticality, exposure, controls) in the inventory is accurate.', 'EPSS/KEV values are only as recent as the last feed import.'], limitations: [v.cvss ? '' : 'No CVSS score is available for this record.', v.epss ? '' : 'No EPSS score has been imported.'].filter(Boolean),
      recommendations: [v.status === 'open' ? `Remediate or mitigate ${v.cve ?? v.title}${v.dueDate ? ` before ${v.dueDate.slice(0, 10)}` : ''}.` : `Status is ${v.status}.`, ...(v.confidence !== 'confirmed' ? ['Verify the finding on the host before investing remediation effort.'] : [])] };
  }
  private async case_(orgId: string, id?: string) {
    const c = await this.db.cases.get(orgId, this.need(id)); if (!c) throw new NotFoundException('case not found');
    const [assets, corr, ev] = await Promise.all([Promise.all(c.assetIds.map((x) => this.db.inventory.get(orgId, x))), c.correlationId ? this.db.correlations.get(orgId, c.correlationId) : undefined, this.db.evidence.where(orgId, { caseId: c.id })]);
    const conf = corr ? corr.confidence : 0.5;
    return { summary: `Case #${c.number} "${c.name}" is ${c.severity}/${c.status}: ${c.signalIds.length} signal(s), ${c.assetIds.length} asset(s), ${c.identityIds.length} identit${c.identityIds.length === 1 ? 'y' : 'ies'}, ${ev.length} evidence item(s).`,
      details: [`Affected assets: ${assets.filter(Boolean).map((a) => a!.name).join(', ') || 'none linked'}.`, ...(corr ? [`Correlation (${corr.status}, confidence ${corr.confidence}): ${corr.reasons.filter((r) => r.type !== 'time').map((r) => `${r.type}=${r.value}`).join(', ')}.`] : ['No correlation backs this case: it was opened manually or by a playbook.']),
        `Timeline: ${c.timeline.length} entries, last "${c.timeline.at(-1)?.text.slice(0, 120) ?? ''}".`, `Actions recorded: ${c.actions.length}.`],
      sources: [{ type: 'case', id: c.id }, ...c.assetIds.map((x) => ({ type: 'asset', id: x })), ...(corr ? [{ type: 'correlation', id: corr.id }] : []), ...ev.map((e) => ({ type: 'evidence', id: e.id }))], confidence: { value: conf, level: lvl(conf), basis: corr ? `correlation confidence ${corr.confidence}${corr.status === 'confirmed' ? ' (confirmed by a human)' : ' (probabilistic)'}` : 'no automated correlation to measure' },
      assumptions: ['Signals attributed to an asset are matched by hostname or IP and may be wrong if names are reused.'], limitations: ['Only data stored in SentinelMesh was considered; activity on systems without a connector is invisible.'],
      recommendations: [...c.recommendations, ...(c.status === 'new' ? ['Assign an owner and move the case to "investigating".'] : [])] };
  }
  private async corr(orgId: string, id?: string) {
    const c = await this.db.correlations.get(orgId, this.need(id)); if (!c) throw new NotFoundException('correlation not found');
    const sigs = (await Promise.all(c.signalIds.map((s) => this.db.signals.get(orgId, s)))).filter(Boolean);
    return { summary: `${c.signalIds.length} signals from ${[...new Set(sigs.map((s) => s!.source))].join(', ')} are probably related (confidence ${c.confidence}, risk ${c.riskScore}/100). Status: ${c.status}.`,
      details: c.reasons.map((r) => `${r.type}: ${r.value} (weight ${r.confidence}, from ${r.source})`), sources: [{ type: 'correlation', id: c.id }, ...c.signalIds.map((s) => ({ type: 'signal', id: s }))], confidence: { value: c.confidence, level: lvl(c.confidence), basis: 'noisy-OR of the strongest reason of each type' },
      assumptions: ['Shared attributes (asset, identity, public IP, domain, CVE) imply a common cause.', 'Private IP addresses are ignored as evidence.'], limitations: ['A correlation is a hypothesis; only a human can confirm it.'], recommendations: c.recommendation };
  }
  private async ident(orgId: string, id?: string) {
    const i = await this.db.identities.get(orgId, this.need(id)); if (!i) throw new NotFoundException('identity not found');
    const risks = (await this.iam.risks(orgId)).filter((r) => r.identityId === i.id), worst = risks.some((r) => r.confidence === 'confirmed') ? 0.9 : 0.5;
    return { summary: `${i.name} (${i.kind}, ${i.provider}) is ${i.privileged ? 'privileged' : 'not privileged'} with ${risks.filter((r) => r.code !== 'privileged').length} access finding(s).`, details: risks.map((r) => `${r.code} [${r.severity}, ${r.confidence}]: ${r.detail}`),
      sources: [{ type: 'identity', id: i.id }], confidence: { value: worst, level: lvl(worst), basis: risks.some((r) => r.confidence === 'confirmed') ? 'findings rest on data supplied by the identity provider' : 'findings are unverified (provider supplied no data)' },
      assumptions: ['Entitlement and activity data from the provider are complete.'], limitations: ['"Unverified" means data was missing, not that the identity is safe.'], recommendations: risks.filter((r) => r.code === 'excessive_permissions').length ? ['Review a least-privilege reduction (proposal only; applying it needs approval).'] : [] };
  }
  private async path(orgId: string, id?: string) {
    const p = (await this.ctem.attackPaths(orgId, { maxPaths: 100 })).find((x) => x.id === this.need(id)); if (!p) throw new NotFoundException('attack path not found (graph may have changed)');
    return { summary: `Theoretical path from ${p.entry.name} to ${p.target.name} in ${p.hops} hop(s), confidence ${p.confidence}, status ${p.status}.`,
      details: [...p.edges.map((e) => `${e.from} —${e.kind}→ ${e.to} (confidence ${e.confidence}, ${e.source})`), p.impact, ...p.evidence.map((x) => `evidence: ${x.type} ${x.detail}`)], sources: [...p.nodes.map((n) => ({ type: n.kind, id: n.id })), ...p.evidence.map((x) => ({ type: x.type, id: x.id }))],
      confidence: { value: p.confidence, level: lvl(p.confidence), basis: 'product of edge confidences and entry-point evidence' }, assumptions: [...p.notes], limitations: ['This is NOT an intrusion: it is what could happen if each relation is exploitable.'],
      recommendations: ['Break the weakest hop: remove an unnecessary trust/permission or fix the vulnerability at the entry point.'] };
  }
  private async prio(orgId: string) {
    const list = (await this.ctem.priorities(orgId)).slice(0, 5);
    return { summary: list.length ? `${list.length} findings need attention first; the top one is ${list[0].cve ?? list[0].title} (${list[0].priority?.level}).` : 'There are no open vulnerabilities to prioritise.', details: list.map((x, n) => `${n + 1}. ${x.cve ?? x.title}: ${x.priority?.explanation}`),
      sources: list.map((x) => ({ type: 'vulnerability', id: x.id })), confidence: { value: list.length ? 0.8 : 0.3, level: (list.length ? 'high' : 'low') as 'high' | 'low', basis: 'deterministic scoring over stored records' }, assumptions: ['Inventory context is current.'], limitations: ['Only open and in-progress findings are ranked.'], recommendations: list.map((x) => `Handle ${x.cve ?? x.title}${x.dueDate ? ` by ${x.dueDate.slice(0, 10)}` : ''}.`) };
  }

  /** Optional external narrative. Off unless the operator configured a provider AND an admin consented for this organisation. */
  private async narrate(me: Principal, e: Explanation) {
    const url = process.env.AI_LLM_URL; const c = await this.consent(me.orgId);
    if (!url || !c?.enabled) throw new ForbiddenException('external AI is not enabled for this organisation (operator configuration + administrator consent are both required)');
    let priv: string[] = []; try { priv = JSON.parse(process.env.AI_PRIVATE_HOSTS ?? '[]'); } catch { /* none */ }
    await assertSafeUrl(url, { allowHttp: process.env.AI_ALLOW_HTTP === '1', allowPrivateHosts: priv });
    const prompt = clean(JSON.stringify(redact({ task: 'Write a short plain-language narrative of this security finding. Use ONLY the facts given; say "unknown" for anything missing. Do not suggest executing actions.', summary: e.summary, details: e.details, assumptions: e.assumptions, limitations: e.limitations })));
    await this.audit.append(me.orgId, me.userId, 'ai.external_call', { kind: e.kind, id: e.id, bytes: prompt.length, provider: new URL(url).host });   // content is never logged
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...(process.env.AI_LLM_KEY ? { authorization: `Bearer ${process.env.AI_LLM_KEY}` } : {}) }, body: JSON.stringify({ prompt }), redirect: 'manual', signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new BadRequestException(`external AI provider answered HTTP ${res.status}`);
    const j = (await res.json()) as { text?: string }; if (typeof j.text !== 'string') throw new BadRequestException('external AI provider returned no text');
    return { text: redactString(j.text).slice(0, 4000), provider: new URL(url).host, notice: 'Generated by an external language model from pseudonymised data. Verify against the sources listed; it may contain errors and it did not execute anything.' };
  }
}
