import type { Criticality, InventoryAsset, PriorityFactor, PriorityResult, Vulnerability } from '../store/enterprise.models';
import type { Severity } from '../store/models';

/**
 * Contextual CTEM prioritisation. It is NOT a CVSS sort: every point comes from a named, documented factor and is returned with the
 * reason, so an analyst can disagree with a specific line instead of a black-box score. Factors only use data that exists:
 * a missing EPSS/KEV/CVSS contributes nothing (and says so) rather than being guessed.
 */
export interface PriorityContext {
  asset?: Pick<InventoryAsset, 'criticality' | 'internetFacing' | 'environment' | 'controls' | 'name'>;
  /** privileged identities reachable from the asset (what an attacker inherits by compromising it) */
  privilegedIdentities?: number;
  /** critical assets that can be reached from this one (blast radius via relations) */
  criticalDependents?: number;
  /** open, confirmed exposure findings on the asset (e.g. the vulnerable service is actually published) */
  openExposures?: number;
}

const SEV_POINTS: Record<Severity, number> = { critical: 36, high: 28, medium: 18, low: 8, info: 2 };
const CRIT_POINTS: Record<Criticality, number> = { critical: 15, high: 10, medium: 5, low: 0 };
const CONF_FACTOR = { confirmed: 1, suspected: 0.7, unverified: 0.4 } as const;
/** Controls that genuinely reduce exploitability of a network-reachable flaw. Each -5, capped at -15. */
const COMPENSATING = new Set(['waf', 'edr', 'segmentation', 'mfa', 'virtual_patch']);

export const LEVELS: Array<[number, PriorityResult['level']]> = [[75, 'immediate'], [55, 'high'], [35, 'medium'], [15, 'low'], [0, 'monitor']];
export const levelFor = (score: number) => LEVELS.find(([min]) => score >= min)![1];

export function prioritize(v: Pick<Vulnerability, 'severity' | 'cvss' | 'epss' | 'kev' | 'confidence' | 'status'>, ctx: PriorityContext = {}, at = new Date().toISOString()): PriorityResult {
  const f: PriorityFactor[] = [];
  const add = (name: string, points: number, detail: string) => f.push({ name, points, detail });

  if (v.cvss) add('Base severity (CVSS)', Math.round(v.cvss.score * 3.6), `CVSS ${v.cvss.score}${v.cvss.version ? ` (v${v.cvss.version})` : ''} × 3.6`);
  else add('Base severity (reported)', SEV_POINTS[v.severity], `no CVSS available; severity "${v.severity}" as reported by the source`);

  if (v.kev) add('Known exploited (CISA KEV)', 25, 'listed in the CISA Known Exploited Vulnerabilities catalogue: exploitation in the wild is documented');
  else add('Known exploited (CISA KEV)', 0, 'not in the imported KEV catalogue (or catalogue not imported)');

  if (v.epss) {
    const p = v.epss.score >= 0.5 ? 15 : v.epss.score >= 0.1 ? 8 : v.epss.score >= 0.01 ? 3 : 0;
    add('Exploit probability (EPSS)', p, `EPSS ${(v.epss.score * 100).toFixed(1)}%${v.epss.asOf ? ` as of ${v.epss.asOf}` : ''}`);
  } else add('Exploit probability (EPSS)', 0, 'no EPSS score imported for this CVE');

  const a = ctx.asset;
  if (a) {
    add('Asset criticality', CRIT_POINTS[a.criticality], `${a.name} is ${a.criticality}`);
    add('External exposure', a.internetFacing ? 10 : 0, a.internetFacing ? 'asset is reachable from the Internet' : 'asset is not Internet-facing');
    if (a.environment === 'dev') add('Environment', -10, 'development environment');
    const ctl = (a.controls ?? []).filter((c) => COMPENSATING.has(c));
    add('Compensating controls', -Math.min(15, ctl.length * 5), ctl.length ? `controls in place: ${ctl.join(', ')}` : 'no compensating controls recorded');
  } else add('Asset context', 0, 'asset not found in the inventory: no context applied (conservative)');

  const pi = ctx.privilegedIdentities ?? 0;
  add('Privileges involved', Math.min(10, pi * 5), pi ? `compromise exposes ${pi} privileged identit${pi === 1 ? 'y' : 'ies'}` : 'no privileged identity reachable from the asset');
  const cd = ctx.criticalDependents ?? 0;
  add('Business impact (blast radius)', cd ? 5 : 0, cd ? `compromise can lead to ${cd} critical asset(s)` : 'no critical asset reachable through recorded relations');
  const ex = ctx.openExposures ?? 0;
  add('Confirmed exposure', ex ? 5 : 0, ex ? `${ex} open exposure finding(s) on the asset` : 'no open exposure findings on the asset');

  const raw = f.reduce((s, x) => s + x.points, 0);
  const factor = CONF_FACTOR[v.confidence];
  if (factor !== 1) add('Detection confidence', Math.round(raw * factor) - raw, `${v.confidence} detection: score scaled ×${factor}`);
  let score = Math.max(0, Math.min(100, Math.round(raw * factor)));
  let level = levelFor(score);
  let override = '';
  if (v.kev && a?.internetFacing && v.confidence === 'confirmed' && v.status !== 'resolved' && level !== 'immediate') {
    level = 'immediate'; score = Math.max(score, 75); override = ' Override: a confirmed, actively exploited flaw on an Internet-facing asset is always immediate.';
  }
  const top = [...f].filter((x) => x.points > 0).sort((x, y) => y.points - x.points).slice(0, 3).map((x) => `${x.name} (+${x.points})`).join(', ');
  const down = f.filter((x) => x.points < 0).map((x) => `${x.name} (${x.points})`).join(', ');
  return { score, level, factors: f, computedAt: at, explanation: `Priority ${level.toUpperCase()} (${score}/100). Main drivers: ${top || 'none'}.${down ? ` Reduced by: ${down}.` : ''}${override}` };
}
