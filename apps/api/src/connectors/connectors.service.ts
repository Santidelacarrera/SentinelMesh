import { BadRequestException, ConflictException, HttpException, HttpStatus, Inject, Injectable, Logger, NotFoundException, OnApplicationShutdown, OnModuleInit } from '@nestjs/common';
import { z } from 'zod';
import { Db } from '../store/db';
import { ConnectorConfig, ConnectorKind, ConnectorRun } from '../store/enterprise.models';
import { AuditTrail } from '../audit/audit-trail';
import { Entitlements } from '../platform/entitlements';
import { CtemService } from '../ctem/ctem.service';
import { IamService } from '../iam/iam.service';
import { SignalsService } from '../signals/signals.service';
import { SecretBox } from '../common/crypto';
import { redactString } from '../common/mask';
import { newId, now } from '../common/ids';
import { EXECUTION_LOCK, ExecutionLock } from '../workflow/lock';
import { PLATFORM_ORG } from '../auth/rbac';
import { Principal } from '../auth/auth';
import { SECRET_BOX } from '../auth/accounts.service';
import { Connector, ConnectorRuntime } from './types';
import { crowdstrike, defender, wazuh } from './edr';
import { entra, googleWorkspace, okta } from './idp';
import { aws, azure, gcp } from './cloud';
import { ConnectorError, HttpClient } from './http';
import { Metrics } from '../ops/metrics';

export const CONNECTORS: Partial<Record<ConnectorKind, Connector>> = { wazuh, crowdstrike, defender, aws, azure, gcp, entra, okta, google_workspace: googleWorkspace };
/** Kinds the model knows but that have no implementation yet (reported honestly instead of faking a connection). */
export const NOT_IMPLEMENTED: Partial<Record<ConnectorKind, string>> = { ad: 'On-premises Active Directory needs an LDAP client; sync it through Microsoft Entra Connect and use the "entra" connector.' };

export const ConnectorSchema = z.object({
  kind: z.enum(['wazuh', 'crowdstrike', 'defender', 'aws', 'azure', 'gcp', 'entra', 'okta', 'google_workspace', 'ad']), name: z.string().min(1).max(120), baseUrl: z.string().max(500).default(''),
  credentials: z.record(z.string(), z.string().max(8000)).optional(), options: z.record(z.string(), z.unknown()).default({}), credentialsExpireAt: z.string().datetime().optional(),
}).strict();
export const ConnectorUpdateSchema = z.object({ name: z.string().min(1).max(120).optional(), baseUrl: z.string().max(500).optional(), credentials: z.record(z.string(), z.string().max(8000)).optional(), options: z.record(z.string(), z.unknown()).optional(), credentialsExpireAt: z.string().datetime().nullable().optional() }).strict();

const LOCAL = /^(localhost|127\.|\[?::1\]?$|.*\.(test|localhost|local|invalid|example)$)/i;
const hostOf = (u: string) => { try { return new URL(u).hostname; } catch { return ''; } };

@Injectable()
export class ConnectorsService implements OnModuleInit, OnApplicationShutdown {
  private log = new Logger('Connectors');
  private timer?: NodeJS.Timeout;
  private clients = new Map<string, HttpClient>();
  constructor(private db: Db, private audit: AuditTrail, private ent: Entitlements, private ctem: CtemService, private iam: IamService, private signals: SignalsService, @Inject(SECRET_BOX) private box: SecretBox, @Inject(EXECUTION_LOCK) private lock: ExecutionLock, private metrics: Metrics) {}

  onModuleInit() {
    const every = Number(process.env.CONNECTOR_SYNC_INTERVAL_SEC ?? 0);
    if (every > 0) { this.timer = setInterval(() => void this.syncAllDue(), every * 1000); this.timer.unref(); }
  }
  onApplicationShutdown() { if (this.timer) clearInterval(this.timer); }
  private async syncAllDue() {
    const orgs = new Set([...(await this.db.orgs.list(PLATFORM_ORG)).map((o) => o.id), ...(process.env.CONNECTOR_SYNC_ORGS ?? '').split(',').filter(Boolean)]);
    for (const orgId of orgs) for (const c of await this.db.connectors.list(orgId, (x) => x.enabled && x.status !== 'not_configured')) await this.sync({ orgId, userId: 'scheduler' }, c.id).catch((e) => this.log.warn(`scheduled sync of ${c.id} failed: ${(e as Error).message}`));
  }

  // ───────── views ─────────
  private view(c: ConnectorConfig) {
    const impl = CONNECTORS[c.kind], local = LOCAL.test(hostOf(c.baseUrl)) || (c.kind === 'aws' && !!c.baseUrl && LOCAL.test(hostOf(c.baseUrl)));
    /** simulated = points at a local/test endpoint; connected = a live test succeeded against a non-local endpoint; implemented = code exists, not verified against a real tenant. */
    const verification = !impl ? 'not_implemented' : local ? 'simulated' : c.lastTestOk ? 'connected' : 'implemented';
    const days = c.credentialsExpireAt ? Math.floor((Date.parse(c.credentialsExpireAt) - Date.now()) / 86400000) : undefined;
    const { credentialsEnc, ...rest } = c;
    return { ...rest, hasCredentials: !!credentialsEnc, verification, requiredPermissions: impl?.permissions ?? [], credentialFields: impl?.credentialFields ?? [], credentialsExpireInDays: days, expiryWarning: days !== undefined && days < 14 };
  }
  private async get(orgId: string, id: string) { const c = await this.db.connectors.get(orgId, id); if (!c) throw new NotFoundException('connector not found'); return c; }
  private log_(c: ConnectorConfig, text: string) { return this.db.connectors.update(c.orgId, c.id, (r) => { r.activity = [{ at: now(), text }, ...r.activity].slice(0, 50); }); }
  private statusFor(c: Pick<ConnectorConfig, 'enabled' | 'credentialsEnc'>): ConnectorConfig['status'] { return !c.enabled ? 'disabled' : c.credentialsEnc ? 'configured' : 'not_configured'; }

  async list(orgId: string) { return (await this.db.connectors.list(orgId)).map((c) => this.view(c)); }
  async detail(orgId: string, id: string) { return { connector: this.view(await this.get(orgId, id)), runs: (await this.db.connectorRuns.where(orgId, { connectorId: id })).sort((a, b) => b.startedAt.localeCompare(a.startedAt)).slice(0, 20) }; }
  /** What exists in code and what each connector needs, independent of any tenant configuration. */
  catalog() { return [...Object.values(CONNECTORS).map((c) => ({ kind: c!.kind, implemented: true, permissions: c!.permissions, credentialFields: c!.credentialFields })), ...Object.entries(NOT_IMPLEMENTED).map(([kind, why]) => ({ kind, implemented: false, reason: why }))]; }

  // ───────── configuration ─────────
  private checkCreds(impl: Connector, creds: Record<string, string>) { const missing = impl.credentialFields.filter((f) => !creds[f]); if (missing.length) throw new BadRequestException(`missing credential fields: ${missing.join(', ')}`); }
  async create(me: Principal, i: z.infer<typeof ConnectorSchema>) {
    if (NOT_IMPLEMENTED[i.kind]) throw new HttpException({ message: `connector "${i.kind}" is not implemented`, reason: NOT_IMPLEMENTED[i.kind] }, HttpStatus.NOT_IMPLEMENTED);
    const impl = CONNECTORS[i.kind]!;
    if (i.kind !== 'aws' && !/^https?:\/\//i.test(i.baseUrl)) throw new BadRequestException('baseUrl must be an http(s) URL');
    if (i.credentials) this.checkCreds(impl, i.credentials);
    await this.ent.assertWithin(me.orgId, 'connectors', (await this.db.connectors.list(me.orgId)).length);
    const id = newId('con');
    const c: ConnectorConfig = { id, orgId: me.orgId, kind: i.kind, name: i.name, enabled: true, baseUrl: i.baseUrl, credentialsEnc: i.credentials ? this.box.encrypt(JSON.stringify(i.credentials), id) : undefined, options: i.options, permissions: [...impl.permissions],
      status: i.credentials ? 'configured' : 'not_configured', credentialsExpireAt: i.credentialsExpireAt, createdAt: now(), activity: [{ at: now(), text: `created by ${me.userId}` }] };
    await this.db.connectors.put(c);
    await this.audit.append(me.orgId, me.userId, 'connector.created', { connectorId: id, kind: i.kind, name: i.name, baseUrl: i.baseUrl });         // never the credentials
    return this.view(c);
  }
  async update(me: Principal, id: string, i: z.infer<typeof ConnectorUpdateSchema>) {
    const c = await this.get(me.orgId, id), impl = CONNECTORS[c.kind]!;
    if (i.credentials) this.checkCreds(impl, i.credentials);
    const out = await this.db.connectors.update(me.orgId, id, (r) => {
      if (i.name) r.name = i.name; if (i.baseUrl !== undefined) r.baseUrl = i.baseUrl; if (i.options) r.options = i.options;
      if (i.credentialsExpireAt !== undefined) r.credentialsExpireAt = i.credentialsExpireAt ?? undefined;
      if (i.credentials) { r.credentialsEnc = this.box.encrypt(JSON.stringify(i.credentials), id); r.lastTestOk = undefined; r.lastError = undefined; r.status = this.statusFor(r); }   // rotated credentials must be re-tested
    });
    await this.audit.append(me.orgId, me.userId, 'connector.updated', { connectorId: id, fields: Object.keys(i), credentialsRotated: !!i.credentials });
    return this.view(out);
  }
  async setEnabled(me: Principal, id: string, enabled: boolean) {
    await this.get(me.orgId, id);
    const out = await this.db.connectors.update(me.orgId, id, (r) => { r.enabled = enabled; r.status = enabled ? (r.lastTestOk ? 'connected' : this.statusFor(r)) : 'disabled'; });
    await this.log_(out, enabled ? 'enabled' : 'disabled');
    await this.audit.append(me.orgId, me.userId, enabled ? 'connector.enabled' : 'connector.disabled', { connectorId: id });
    return this.view(out);
  }

  // ───────── runtime ─────────
  private runtime(c: ConnectorConfig, fetchImpl?: typeof fetch): ConnectorRuntime {
    if (!c.credentialsEnc) throw new BadRequestException('connector has no credentials');
    const impl = CONNECTORS[c.kind]!, creds = JSON.parse(this.box.decrypt(c.credentialsEnc, c.id)) as Record<string, string>;
    const base = { orgId: c.orgId, config: c, creds, fetch: fetchImpl };
    // The HTTP client (and its OAuth token cache) is reused across test/sync calls until credentials, URL or options change, so tokens are not re-issued per call.
    const key = `${c.id}|${c.credentialsEnc}|${c.baseUrl}|${JSON.stringify(c.options)}`;
    let http = fetchImpl ? undefined : this.clients.get(key);
    if (!http) { http = impl.prepare(base); if (!fetchImpl) { for (const k of [...this.clients.keys()]) if (k.startsWith(`${c.id}|`)) this.clients.delete(k); this.clients.set(key, http); } }
    return { ...base, http };
  }
  private fail(e: unknown) { return redactString(e instanceof ConnectorError || e instanceof Error ? e.message : String(e)).slice(0, 500); }

  async test(me: Pick<Principal, 'orgId' | 'userId'>, id: string, fetchImpl?: typeof fetch) {
    const c = await this.get(me.orgId, id); if (!c.enabled) throw new ConflictException('connector is disabled');
    let ok = false, detail: string;
    try { const r = await CONNECTORS[c.kind]!.test(this.runtime(c, fetchImpl)); ok = r.ok; detail = r.detail; } catch (e) { if (e instanceof BadRequestException) throw e; detail = this.fail(e); }
    const out = await this.db.connectors.update(me.orgId, id, (r) => { r.lastTestAt = now(); r.lastTestOk = ok; r.lastError = ok ? undefined : detail; r.status = ok ? 'connected' : 'error'; });
    await this.log_(out, `connection test ${ok ? 'OK' : 'FAILED'}: ${detail}`);
    await this.audit.append(me.orgId, me.userId, 'connector.tested', { connectorId: id, ok, detail });
    return { ok, detail, connector: this.view(out) };
  }

  async sync(me: Pick<Principal, 'orgId' | 'userId'>, id: string, fetchImpl?: typeof fetch) {
    const c = await this.get(me.orgId, id);
    if (!c.enabled) throw new ConflictException('connector is disabled');
    const release = await this.lock.acquire(`connector-sync:${me.orgId}:${id}`, 300_000).catch(() => { throw new ConflictException('a sync is already running for this connector'); });
    const run: ConnectorRun = { id: newId('run'), orgId: me.orgId, connectorId: id, startedAt: now(), status: 'running', counts: {} };
    try {
      await this.db.connectorRuns.put(run); await this.db.connectors.update(me.orgId, id, { status: 'syncing' });
      const res = await CONNECTORS[c.kind]!.sync(this.runtime(c, fetchImpl));
      const counts: Record<string, number> = { assets: 0, identities: 0, signals: 0, vulns: 0, failed: 0 }, actor = { orgId: me.orgId, userId: `connector:${c.kind}` };
      for (const a of res.assets) { try { await this.ctem.upsertAsset(actor, a); counts.assets++; } catch { counts.failed++; } }
      if (await this.ent.has(me.orgId, 'iam')) for (const i of res.identities) { try { await this.iam.upsert(actor, i); counts.identities++; } catch { counts.failed++; } }
      const assets = await this.db.inventory.list(me.orgId), byHost = new Map(assets.flatMap((a) => [[a.identifier.toLowerCase(), a], [a.name.toLowerCase(), a]] as const));
      for (const v of res.vulns) { const a = byHost.get(v.host.toLowerCase()); if (!a) { counts.failed++; continue; } try { await this.ctem.createVuln({ ...actor, role: 'analyst', email: '' } as Principal, { assetId: a.id, cve: v.cve, title: v.title, description: '', severity: v.severity, cvss: v.cvss ? { score: v.cvss } : undefined, confidence: 'suspected', evidence: v.evidence, source: `connector:${c.kind}` }); counts.vulns++; } catch { counts.failed++; } }
      const sg = await this.signals.ingest(me.orgId, actor.userId, res.signals); counts.signals = sg.created;
      const done = await this.db.connectors.update(me.orgId, id, (r) => { r.status = 'connected'; r.lastSyncAt = now(); r.lastError = undefined; r.lastTestOk = true; if (res.cursor) r.cursor = res.cursor; });
      await this.db.connectorRuns.update(me.orgId, run.id, { status: 'ok', finishedAt: now(), counts });
      await this.log_(done, `sync OK: ${JSON.stringify(counts)}`);
      this.metrics.inc('sentinel_connector_syncs_total', { kind: c.kind }, 1, 'successful connector synchronisations');
      await this.audit.append(me.orgId, me.userId, 'connector.synced', { connectorId: id, kind: c.kind, counts });
      return { runId: run.id, counts, connector: this.view(done) };
    } catch (e) {
      const msg = this.fail(e);
      this.metrics.inc('sentinel_connector_sync_failures_total', { kind: c.kind }, 1, 'failed connector synchronisations');
      const bad = await this.db.connectors.update(me.orgId, id, (r) => { r.status = 'error'; r.lastError = msg; });
      await this.db.connectorRuns.update(me.orgId, run.id, { status: 'error', finishedAt: now(), error: msg }).catch(() => undefined);
      await this.log_(bad, `sync FAILED: ${msg}`);
      await this.audit.append(me.orgId, me.userId, 'connector.sync_failed', { connectorId: id, kind: c.kind, error: msg });
      throw new HttpException({ message: 'sync failed', error: msg, connector: this.view(bad) }, HttpStatus.BAD_GATEWAY);
    } finally { await release(); }
  }

  /** For the dashboard and metrics: real states only (no connector appears "connected" unless a test or sync succeeded). */
  async health(orgId: string) {
    const all = await this.db.connectors.list(orgId), by: Record<string, number> = {};
    for (const c of all) by[c.status] = (by[c.status] ?? 0) + 1;
    return { total: all.length, byStatus: by, failing: all.filter((c) => c.status === 'error').map((c) => ({ id: c.id, name: c.name, kind: c.kind, error: c.lastError })), expiringCredentials: all.filter((c) => c.credentialsExpireAt && Date.parse(c.credentialsExpireAt) - Date.now() < 14 * 86400000).map((c) => ({ id: c.id, name: c.name, expiresAt: c.credentialsExpireAt })) };
  }
}
