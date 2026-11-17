import type { Identity, InventoryAsset, Relation, RelationKind, Vulnerability, ExposureFinding, Signal } from '../store/enterprise.models';

/**
 * Attack-path analysis over the exposure graph. Nodes are inventory assets and identities; edges are recorded relations.
 * Every returned path is THEORETICAL ("an attacker who compromises X could reach Y if each hop holds"): it is only labelled
 * `corroborated` when open alerts exist on nodes of the path, and is never presented as a confirmed intrusion.
 *
 * Edge semantics (movement of an attacker): `from → to` for every kind except `runs_on` (a container that `runs_on` a host is
 * reached by compromising the host, so movement is host → container).
 */
export interface PathNode { id: string; kind: 'asset' | 'identity'; name: string; type: string; criticality?: string; privileged?: boolean; internetFacing?: boolean }
export interface PathEdge { from: string; to: string; kind: RelationKind; source: string; confidence: number; evidence?: string }
export interface AttackPath {
  id: string; entry: PathNode; target: PathNode; nodes: PathNode[]; edges: PathEdge[]; hops: number;
  privileges: Array<{ identity: string; privileged: boolean; entitlements: string[] }>;
  impact: string; evidence: Array<{ type: 'vulnerability' | 'exposure' | 'signal'; id: string; node: string; detail: string }>;
  /** 0..1: product of edge confidences and of the weakest entry-evidence factor. Not a probability of attack. */
  confidence: number; status: 'theoretical' | 'corroborated'; notes: string[];
}
export interface GraphInput { assets: InventoryAsset[]; identities: Identity[]; relations: Relation[]; vulns: Vulnerability[]; exposures: ExposureFinding[]; signals: Signal[] }
export interface PathOptions { maxDepth?: number; maxPaths?: number; minConfidence?: number; targets?: string[] }

const reversed = (k: RelationKind) => k === 'runs_on';

export function analyzeAttackPaths(g: GraphInput, o: PathOptions = {}): AttackPath[] {
  const maxDepth = o.maxDepth ?? 6, maxPaths = o.maxPaths ?? 25, minConf = o.minConfidence ?? 0.05;
  const nodes = new Map<string, PathNode>();
  for (const a of g.assets) if (a.status !== 'retired') nodes.set(a.id, { id: a.id, kind: 'asset', name: a.name, type: a.type, criticality: a.criticality, internetFacing: a.internetFacing });
  for (const i of g.identities) if (i.status === 'active') nodes.set(i.id, { id: i.id, kind: 'identity', name: i.name, type: i.kind, privileged: i.privileged });

  // adjacency (attacker movement); identity.assetIds are implicit has_access edges at moderate confidence
  const adj = new Map<string, PathEdge[]>();
  const link = (e: PathEdge) => { if (!nodes.has(e.from) || !nodes.has(e.to)) return; (adj.get(e.from) ?? adj.set(e.from, []).get(e.from)!).push(e); };
  for (const r of g.relations) {
    const [from, to] = reversed(r.kind) ? [r.to, r.from] : [r.from, r.to];
    link({ from, to, kind: r.kind, source: r.source, confidence: r.confidence, evidence: r.evidence });
  }
  for (const i of g.identities) for (const a of i.assetIds) link({ from: i.id, to: a, kind: 'has_access', source: i.provider, confidence: 0.6, evidence: `${i.name} has recorded access to the asset` });

  const openVulns = g.vulns.filter((v) => v.status !== 'resolved' && v.status !== 'accepted');
  const openExp = g.exposures.filter((e) => e.status === 'open');
  const alertsBy = new Map<string, Signal[]>();
  for (const s of g.signals) for (const id of [s.assetId, s.identityId]) if (id) (alertsBy.get(id) ?? alertsBy.set(id, []).get(id)!).push(s);

  // entry points: Internet-facing assets. Entry evidence decides how credible the foothold is.
  const entries = g.assets.filter((a) => a.internetFacing && a.status === 'active');
  const targets = new Set(o.targets ?? g.assets.filter((a) => a.criticality === 'critical' && a.status !== 'retired').map((a) => a.id));
  const out: AttackPath[] = [];

  for (const entry of entries) {
    const footholds = [
      ...openVulns.filter((v) => v.assetId === entry.id).map((v) => ({ type: 'vulnerability' as const, id: v.id, node: entry.id, detail: `${v.cve ?? v.title} (${v.confidence}${v.kev ? ', KEV' : ''})`, factor: v.confidence === 'confirmed' ? 1 : v.confidence === 'suspected' ? 0.7 : 0.4 })),
      ...openExp.filter((e) => e.assetId === entry.id).map((e) => ({ type: 'exposure' as const, id: e.id, node: entry.id, detail: e.title, factor: e.confidence === 'confirmed' ? 0.9 : 0.5 })),
    ];
    const entryFactor = footholds.length ? Math.max(...footholds.map((x) => x.factor)) : 0.15;     // no known weakness: purely hypothetical foothold
    const seen = new Set<string>([entry.id]);
    const walk = (at: string, trail: PathEdge[], conf: number) => {
      if (out.length >= maxPaths * 8) return;
      if (trail.length > 0 && targets.has(at)) { out.push(build(entry, at, trail, conf * entryFactor, footholds)); return; }
      if (trail.length >= maxDepth) return;
      for (const e of adj.get(at) ?? []) {
        if (seen.has(e.to)) continue;
        const c = conf * e.confidence; if (c * entryFactor < minConf) continue;
        seen.add(e.to); walk(e.to, [...trail, e], c); seen.delete(e.to);
      }
    };
    walk(entry.id, [], 1);
  }

  function build(entry: InventoryAsset, targetId: string, trail: PathEdge[], conf: number, footholds: Array<{ type: 'vulnerability' | 'exposure'; id: string; node: string; detail: string }>): AttackPath {
    const ids = [entry.id, ...trail.map((e) => e.to)], ns = ids.map((i) => nodes.get(i)!);
    const evidence: AttackPath['evidence'] = footholds.map(({ type, id, node, detail }) => ({ type, id, node, detail }));
    for (const id of ids) for (const s of alertsBy.get(id) ?? []) evidence.push({ type: 'signal', id: s.id, node: id, detail: `${s.source}: ${s.title}` });
    const corroborated = ids.some((i) => alertsBy.has(i));
    const privs = ns.filter((n) => n.kind === 'identity').map((n) => { const idn = g.identities.find((x) => x.id === n.id)!; return { identity: idn.name, privileged: idn.privileged, entitlements: idn.entitlements.slice(0, 10) }; });
    const t = ns[ns.length - 1];
    const notes = [footholds.length ? '' : 'Entry point has no recorded vulnerability or exposure: foothold is hypothetical.', 'Theoretical path: each hop assumes the relation is exploitable.'].filter(Boolean);
    return { id: `path_${ids.join('>')}`, entry: ns[0], target: t, nodes: ns, edges: trail, hops: trail.length, privileges: privs, impact: `Compromise could reach ${t.name} (${t.criticality ?? t.type})${privs.some((p) => p.privileged) ? ' using privileged identities' : ''}.`, evidence, confidence: Math.round(conf * 1000) / 1000, status: corroborated ? 'corroborated' : 'theoretical', notes };
  }

  return out.sort((a, b) => b.confidence - a.confidence || a.hops - b.hops).slice(0, maxPaths);
}
