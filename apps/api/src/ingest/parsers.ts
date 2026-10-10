import { z } from 'zod';
import { Severity } from '../store/models';
import { sha256 } from '../common/ids';
import { maskSecret, redactString } from '../common/mask';

export interface RawFinding {
  kind: 'vulnerability' | 'secret';
  ruleId: string; title: string; description: string; severity: Severity;
  assetName?: string; location?: string; maskedSecret?: string; secretFingerprint?: string;
  likelyFalsePositive?: boolean;
}
export type ReportFormat = 'sarif' | 'trivy' | 'semgrep' | 'zap' | 'secrets';

const sev = (s: string | undefined): Severity => {
  const v = (s ?? '').toLowerCase();
  if (['critical', 'error'].includes(v)) return v === 'error' ? 'high' : 'critical';
  if (['high'].includes(v)) return 'high';
  if (['medium', 'moderate', 'warning', 'warn'].includes(v)) return 'medium';
  if (['low', 'note'].includes(v)) return 'low';
  return 'info';
};

const Sarif = z.object({
  runs: z.array(z.object({
    tool: z.object({ driver: z.object({ name: z.string().optional(), rules: z.array(z.object({ id: z.string(), properties: z.record(z.string(), z.unknown()).optional() }).passthrough()).optional() }).passthrough() }),
    results: z.array(z.object({
      ruleId: z.string().optional(), level: z.string().optional(),
      message: z.object({ text: z.string().optional() }).optional(),
      locations: z.array(z.object({ physicalLocation: z.object({ artifactLocation: z.object({ uri: z.string().optional() }).optional(), region: z.object({ startLine: z.number().optional() }).optional() }).optional() })).optional(),
      properties: z.record(z.string(), z.unknown()).optional(),
    }).passthrough()).default([]),
  }).passthrough()),
}).passthrough();

export function parseSarif(doc: unknown): RawFinding[] {
  const p = Sarif.parse(doc);
  return p.runs.flatMap((run) => {
    const rules = new Map((run.tool.driver.rules ?? []).map((r) => [r.id, r]));
    return run.results.map((r): RawFinding => {
      const loc = r.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri;
      const rule = rules.get(r.ruleId ?? '');
      const secSev = Number((r.properties?.['security-severity'] ?? rule?.properties?.['security-severity']) ?? NaN);
      const severity = Number.isFinite(secSev) ? (secSev >= 9 ? 'critical' : secSev >= 7 ? 'high' : secSev >= 4 ? 'medium' : 'low') : sev(r.level);
      return {
        kind: 'vulnerability', ruleId: r.ruleId ?? 'unknown', title: redactString(r.message?.text?.split('\n')[0] ?? r.ruleId ?? 'finding'),
        description: redactString(r.message?.text ?? ''), severity,
        location: uri ? `${uri}${loc?.region?.startLine ? ':' + loc.region.startLine : ''}` : undefined,
        assetName: assetFromPath(uri),
        likelyFalsePositive: isTestPath(uri),
      };
    });
  });
}

const Trivy = z.object({ Results: z.array(z.object({ Target: z.string(), Vulnerabilities: z.array(z.object({ VulnerabilityID: z.string(), PkgName: z.string().optional(), InstalledVersion: z.string().optional(), FixedVersion: z.string().optional(), Severity: z.string().optional(), Title: z.string().optional(), Description: z.string().optional() })).nullish() })).default([]) });
export function parseTrivy(doc: unknown): RawFinding[] {
  return Trivy.parse(doc).Results.flatMap((r) => (r.Vulnerabilities ?? []).map((v): RawFinding => ({
    kind: 'vulnerability', ruleId: v.VulnerabilityID, title: v.Title ?? `${v.VulnerabilityID} in ${v.PkgName}`,
    description: redactString(`${v.Description ?? ''} ${v.PkgName}@${v.InstalledVersion}${v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : ''}`.trim()),
    severity: sev(v.Severity), assetName: r.Target, location: `${r.Target}#${v.PkgName}`,
  })));
}

const Semgrep = z.object({ results: z.array(z.object({ check_id: z.string(), path: z.string(), start: z.object({ line: z.number() }).optional(), extra: z.object({ message: z.string().optional(), severity: z.string().optional() }).optional() })).default([]) });
export function parseSemgrep(doc: unknown): RawFinding[] {
  return Semgrep.parse(doc).results.map((r): RawFinding => ({
    kind: 'vulnerability', ruleId: r.check_id, title: redactString(r.extra?.message?.split('\n')[0] ?? r.check_id), description: redactString(r.extra?.message ?? ''),
    severity: sev(r.extra?.severity), location: `${r.path}${r.start ? ':' + r.start.line : ''}`, assetName: assetFromPath(r.path), likelyFalsePositive: isTestPath(r.path),
  }));
}

const Zap = z.object({ site: z.array(z.object({ '@name': z.string().optional(), alerts: z.array(z.object({ pluginid: z.string(), name: z.string(), riskcode: z.union([z.string(), z.number()]), desc: z.string().optional(), instances: z.array(z.object({ uri: z.string().optional() })).optional() })).default([]) })).default([]) });
export function parseZap(doc: unknown): RawFinding[] {
  const risk = ['info', 'low', 'medium', 'high', 'critical'] as const;
  return Zap.parse(doc).site.flatMap((s) => s.alerts.map((a): RawFinding => ({
    kind: 'vulnerability', ruleId: `zap-${a.pluginid}`, title: a.name, description: redactString(a.desc ?? ''),
    severity: risk[Math.min(4, Number(a.riskcode))] ?? 'info', assetName: s['@name'], location: a.instances?.[0]?.uri,
  })));
}

/** Secret-scanner webhook (gitleaks/trufflehog-shaped). The raw secret is masked immediately and never stored. */
const SecretHook = z.object({ findings: z.array(z.object({ rule: z.string(), secret: z.string().min(1), file: z.string().optional(), line: z.number().optional(), repo: z.string().optional(), verified: z.boolean().optional(), entropy: z.number().optional() })) });
export function parseSecrets(doc: unknown): RawFinding[] {
  return SecretHook.parse(doc).findings.map((f): RawFinding => {
    const placeholder = /(^|[^a-z0-9])(example|dummy|changeme|placeholder|your[_-]?(api[_-]?)?(key|token|secret)|x{4,})/i.test(f.secret) || (f.entropy !== undefined && f.entropy < 2.5);
    return {
      kind: 'secret', ruleId: f.rule, title: `Credencial expuesta (${f.rule})`,
      description: `Secreto ${maskSecret(f.secret)} detectado en ${f.file ?? 'el repositorio'}${f.verified ? ' (verificado como activo)' : ''}`,
      severity: f.verified ? 'critical' : 'high', assetName: f.repo, location: f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : undefined,
      maskedSecret: maskSecret(f.secret), secretFingerprint: sha256(f.secret).slice(0, 16),
      likelyFalsePositive: !f.verified && (placeholder || isTestPath(f.file)),
    };
  });
}

function isTestPath(p?: string) { return !!p && /(^|\/)(tests?|__tests__|fixtures?|examples?|docs?)\//i.test(p); }
function assetFromPath(p?: string) { return p ? p.split('/').filter(Boolean)[0] : undefined; }

export const PARSERS: Record<ReportFormat, (doc: unknown) => RawFinding[]> = { sarif: parseSarif, trivy: parseTrivy, semgrep: parseSemgrep, zap: parseZap, secrets: parseSecrets };

export function fingerprint(f: RawFinding): string {
  return sha256([f.kind, f.ruleId, f.assetName ?? '', f.location ?? '', f.secretFingerprint ?? ''].join('|')).slice(0, 32);
}
