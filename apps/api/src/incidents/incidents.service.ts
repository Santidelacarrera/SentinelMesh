import { BadRequestException, Inject, Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { SecurityIncident, Severity } from '../store/models';
import { WorkflowEngine } from '../workflow/engine';
import { DryRunService } from '../remediation/dryrun.service';
import { AnalyticsClient, EvidenceItem } from '../analytics/analytics.client';
import { AuditTrail } from '../audit/audit-trail';
import { OBJECT_STORAGE, ObjectStorage } from '../storage/object-storage';
import { PORTS, ForensicCollector } from '../workflow/ports';
import { newId, now, sha256 } from '../common/ids';
import { redact } from '../common/mask';
import { Principal } from '../auth/auth';

export const TriggerSchema = z.object({
  kind: z.enum(['brute_force', 'request_spike']),
  source: z.string().min(1).max(200),   // offending client (IP / principal)
  target: z.string().min(1).max(200),   // affected service
  count: z.number().int().min(1).max(1e9),
  windowSec: z.number().int().min(1).max(86400),
  gatewayLogs: z.array(z.string().max(2000)).max(500).default([]),
}).strict();

/** Thresholds are per-minute normalised so a long window cannot dilute an attack into silence. */
const THRESHOLD_PER_MIN = { brute_force: 10, request_spike: 600 } as const;

@Injectable()
export class IncidentsService implements OnModuleInit {
  constructor(
    private db: Db, private engine: WorkflowEngine, private dryrun: DryRunService, private analytics: AnalyticsClient, private audit: AuditTrail,
    @Inject(OBJECT_STORAGE) private storage: ObjectStorage, @Inject(PORTS.FORENSICS) private collector: ForensicCollector,
  ) {}

  onModuleInit() {
    this.engine.register('collect_forensics', async (c) => {
      // Captured at the exact moment of the alert, BEFORE any containment, then frozen (write-once, hashed).
      const incidentId = String(c.input['incidentId']);
      const inc = this.db.incidents.get(c.orgId, incidentId)!;
      const bundle = redact(await this.collector.collect(inc.target, c.input));
      const body = JSON.stringify({ incidentId, capturedAt: now(), ...bundle });
      const objectKey = `forensics/${c.orgId}/${incidentId}.json`;
      if (!(await this.storage.get(objectKey))) await this.storage.put(objectKey, body); // write-once: replays never overwrite evidence
      const stored = (await this.storage.get(objectKey))!.toString();
      const existing = this.db.snapshots.list(c.orgId, (s) => s.incidentId === incidentId)[0];
      const snap = existing ?? this.db.snapshots.put({ id: newId('snap'), orgId: c.orgId, incidentId, objectKey, sha256: sha256(stored), items: ['metrics', 'logs', 'containerState'], capturedAt: now() });
      this.db.incidents.update(c.orgId, incidentId, { snapshotId: snap.id });
      return { snapshotId: snap.id, sha256: snap.sha256 };
    });
    this.engine.register('summarize', async (c) => {
      const incidentId = String(c.input['incidentId']);
      const { evidence } = await this.loadEvidence(c.orgId, incidentId);
      const s = await this.analytics.summarize(evidence);
      this.db.incidents.update(c.orgId, incidentId, { summary: s.summary });
      return { citations: s.citations.length };
    });
    this.engine.register('notify', async (c) => ({ notified: 'secops', incidentId: c.input['incidentId'] }));
  }

  async trigger(me: Principal, input: z.infer<typeof TriggerSchema>) {
    const perMin = (input.count * 60) / input.windowSec;
    const anomaly = this.db.anomalies.put({ id: newId('ano'), orgId: me.orgId, kind: input.kind, source: input.source, target: input.target, count: input.count, windowSec: input.windowSec, createdAt: now() });
    this.audit.append(me.orgId, me.userId, 'anomaly.received', { anomalyId: anomaly.id, kind: input.kind, source: input.source, target: input.target, perMin: Math.round(perMin) });
    if (perMin < THRESHOLD_PER_MIN[input.kind]) return { anomalyId: anomaly.id, incidentId: null, triggered: false, reason: `below threshold (${Math.round(perMin)}/min < ${THRESHOLD_PER_MIN[input.kind]}/min)` };

    const severity: Severity = perMin >= THRESHOLD_PER_MIN[input.kind] * 5 ? 'critical' : 'high';
    const inc: SecurityIncident = this.db.incidents.put({ id: newId('inc'), orgId: me.orgId, anomalyId: anomaly.id, severity, target: input.target, status: 'open', createdAt: now() });
    const plan = this.dryrun.simulate(me.orgId, { kind: 'isolation', targetRef: input.target, params: { reason: `${input.kind} from ${input.source}` } });
    const ex = await this.engine.start(me.orgId, 'incident-response',
      { incidentId: inc.id, count: input.count, gatewayLogs: input.gatewayLogs, plans: { 'isolate-service': plan.id } }, me.userId, inc.id);
    this.db.incidents.update(me.orgId, inc.id, { executionId: ex.id, status: 'awaiting_approval' });
    return { anomalyId: anomaly.id, incidentId: inc.id, triggered: true, executionId: ex.id, planId: plan.id, severity };
  }

  private async loadEvidence(orgId: string, incidentId: string) {
    const snap = this.db.snapshots.list(orgId, (s) => s.incidentId === incidentId)[0];
    if (!snap) throw new NotFoundException('no forensic snapshot yet');
    const raw = await this.storage.get(snap.objectKey);
    if (!raw || sha256(raw.toString()) !== snap.sha256) throw new BadRequestException('forensic package failed integrity check');
    const b = JSON.parse(raw.toString()) as { metrics: unknown; logs: string[]; containerState: unknown };
    const evidence: EvidenceItem[] = [
      { id: 'ev-metrics', type: 'metrics', text: JSON.stringify(b.metrics) },
      { id: 'ev-container', type: 'container', text: JSON.stringify(b.containerState) },
      ...b.logs.map((l, i) => ({ id: `ev-log-${i + 1}`, type: 'log', text: l })),
    ];
    return { snap, bundle: b, evidence };
  }

  /** GET /executions/{id}/forensics */
  async forensics(orgId: string, executionId: string) {
    const ex = this.db.executions.get(orgId, executionId);
    if (!ex?.incidentId) throw new NotFoundException('execution has no forensic package');
    const { snap, bundle } = await this.loadEvidence(orgId, ex.incidentId);
    const inc = this.db.incidents.get(orgId, ex.incidentId)!;
    return { incident: { id: inc.id, severity: inc.severity, target: inc.target, summary: inc.summary }, snapshot: { id: snap.id, sha256: snap.sha256, capturedAt: snap.capturedAt, integrity: 'verified' }, evidence: bundle };
  }

  getIncident(orgId: string, id: string) {
    const inc = this.db.incidents.get(orgId, id); if (!inc) throw new NotFoundException();
    const ex = inc.executionId ? this.db.executions.get(orgId, inc.executionId) : undefined;
    const status = ex?.status === 'succeeded' ? 'contained' : ex?.status === 'rejected' ? 'open' : inc.status;
    return { ...inc, status };
  }
}
