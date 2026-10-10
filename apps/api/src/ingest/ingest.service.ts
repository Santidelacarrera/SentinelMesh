import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { AssetContext, CredentialRecord, Finding, Severity, VulnerabilityScan } from '../store/models';
import { PARSERS, fingerprint, ReportFormat, RawFinding } from './parsers';
import { AnalyticsClient } from '../analytics/analytics.client';
import { OBJECT_STORAGE, ObjectStorage } from '../storage/object-storage';
import { AuditTrail } from '../audit/audit-trail';
import { newId, now, sha256 } from '../common/ids';

export const IngestSchema = z.object({
  format: z.enum(['sarif', 'trivy', 'semgrep', 'zap', 'secrets']),
  source: z.string().min(1).max(200),
  report: z.unknown().refine((v) => v !== undefined && v !== null, 'report is required'),
}).strict();

export const AssetSchema = z.object({
  name: z.string().min(1).max(200), internetFacing: z.boolean(), behindGateway: z.boolean().default(false),
  handlesCriticalData: z.boolean().default(false), environment: z.enum(['prod', 'staging', 'dev']).default('prod'),
}).strict();

const SEV: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

@Injectable()
export class IngestService {
  constructor(private db: Db, private analytics: AnalyticsClient, @Inject(OBJECT_STORAGE) private storage: ObjectStorage, private audit: AuditTrail) {}

  upsertAsset(orgId: string, a: z.infer<typeof AssetSchema>): AssetContext {
    const ex = this.db.assets.list(orgId, (x) => x.name === a.name)[0];
    return this.db.assets.put({ ...a, id: ex?.id ?? newId('ast'), orgId });
  }

  async ingest(orgId: string, actor: string, input: z.infer<typeof IngestSchema>) {
    let raws: RawFinding[];
    try { raws = PARSERS[input.format as ReportFormat](input.report); }
    catch (e) { throw new BadRequestException(`report does not match ${input.format} format: ${(e as Error).message.slice(0, 300)}`); }

    // Raw report is archived AFTER redaction of secrets (scanner payloads contain the live secret).
    const archived = JSON.stringify(IngestService.scrub(input.format, input.report));
    const scanId = newId('scan'); const reportRef = `reports/${orgId}/${scanId}.json`;
    await this.storage.put(reportRef, archived);

    const scan: VulnerabilityScan = { id: scanId, orgId, source: input.source, format: input.format, reportRef, reportSha256: sha256(archived), findingCount: 0, createdAt: now() };
    const result = { created: 0, duplicates: 0, suppressed: 0 };
    for (const raw of raws) {
      const fp = fingerprint(raw);
      if (this.db.findings.list(orgId, (f) => f.fingerprint === fp && f.status !== 'resolved').length) { result.duplicates++; continue; }
      const asset = raw.assetName ? this.db.assets.list(orgId, (a) => a.name === raw.assetName)[0] : undefined;
      const c = await this.analytics.correlate({ ruleId: raw.ruleId, kind: raw.kind, severity: raw.severity, likelyFalsePositive: raw.likelyFalsePositive, asset });
      let credentialId: string | undefined;
      if (raw.kind === 'secret' && !c.suppressed) {
        const cred: CredentialRecord = { id: newId('cred'), orgId, name: raw.title, service: raw.assetName ?? 'unknown', kind: 'api_key', currentVersion: 1, maskedValue: raw.maskedSecret!, status: 'exposed' };
        credentialId = this.db.credentials.put(cred).id;
      }
      const f: Finding = {
        id: newId('fnd'), orgId, scanId, kind: raw.kind, fingerprint: fp, ruleId: raw.ruleId, title: raw.title, description: raw.description,
        baseSeverity: raw.severity, severity: c.severity, exposureScore: c.exposureScore, assetName: raw.assetName, location: raw.location,
        status: c.suppressed ? 'suppressed' : 'open', suppressionReason: c.suppressionReason, rationale: c.rationale,
        maskedSecret: raw.maskedSecret, credentialId, remediationPlanIds: [], createdAt: now(),
      };
      this.db.findings.put(f);
      c.suppressed ? result.suppressed++ : result.created++;
    }
    scan.findingCount = result.created + result.suppressed;
    this.db.scans.put(scan);
    this.audit.append(orgId, actor, 'scan.ingested', { scanId, source: input.source, format: input.format, reportSha256: scan.reportSha256, ...result });
    return { scanId, reportRef, ...result };
  }

  /** Redacts raw secret values from a scanner webhook payload before it is archived. */
  private static scrub(format: string, report: unknown) {
    if (format !== 'secrets') return report;
    const r = structuredClone(report) as { findings?: Array<{ secret?: string }> };
    for (const f of r.findings ?? []) if (typeof f.secret === 'string') f.secret = '[REDACTED]';
    return r;
  }

  summary(orgId: string) {
    const all = this.db.findings.list(orgId);
    const open = all.filter((f) => f.status === 'open' || f.status === 'remediating');
    const bySeverity = Object.fromEntries(SEV.map((s) => [s, open.filter((f) => f.severity === s).length]));
    const byAsset: Record<string, number> = {};
    for (const f of open) byAsset[f.assetName ?? 'unknown'] = (byAsset[f.assetName ?? 'unknown'] ?? 0) + 1;
    const top = [...open].sort((a, b) => b.exposureScore - a.exposureScore).slice(0, 10)
      .map((f) => ({ id: f.id, title: f.title, severity: f.severity, baseSeverity: f.baseSeverity, exposureScore: f.exposureScore, asset: f.assetName, kind: f.kind }));
    return { totals: { open: open.length, suppressed: all.filter((f) => f.status === 'suppressed').length, secrets: open.filter((f) => f.kind === 'secret').length }, bySeverity, byAsset, top };
  }

  /** Full traceability: finding → originating report → mitigation plans. */
  trace(orgId: string, findingId: string) {
    const finding = this.db.findings.get(orgId, findingId);
    if (!finding) throw new NotFoundException('finding not found');
    const scan = this.db.scans.get(orgId, finding.scanId);
    const plans = finding.remediationPlanIds.map((id) => this.db.plans.get(orgId, id)).filter(Boolean);
    return { finding, scan, plans };
  }
}
