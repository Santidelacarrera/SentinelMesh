import { Connector, ConnectorRuntime, SyncResult, emptySync, isoOr, sevFromScore, sevFromText } from './types';
import { ConnectorError, HttpClient, TokenManager, connectorUrlPolicy } from './http';

const MAX_PAGES = 20;
const lc = (s: unknown) => (typeof s === 'string' ? s.toLowerCase() : undefined);
const mkHttp = (rt: Omit<ConnectorRuntime, 'http'>, secrets: string[]) => new HttpClient({ baseUrl: rt.config.baseUrl, fetch: rt.fetch, rps: Number(rt.config.options['rps'] ?? 5), secrets, policy: connectorUrlPolicy() });
const basic = (u: string, p: string) => `Basic ${Buffer.from(`${u}:${p}`).toString('base64')}`;

// ─────────────────────────── Wazuh ───────────────────────────
/** Wazuh server API (JWT from /security/user/authenticate) for agents; alerts and vulnerabilities come from the Wazuh indexer when `options.indexerUrl` is set. */
export const wazuh: Connector = {
  kind: 'wazuh', credentialFields: ['username', 'password'],
  permissions: ['Wazuh API role: agent:read, manager:read (read-only)', 'Wazuh indexer user with read on wazuh-alerts-* and wazuh-states-vulnerabilities-* (optional)'],
  prepare(rt) {
    const http = mkHttp(rt, [rt.creds['password'], rt.creds['indexerPassword']]);
    http.tokenProvider = new TokenManager(async () => {
      const r = await http.post<string>('security/user/authenticate', { query: { raw: 'true' }, noAuth: true, headers: { authorization: basic(rt.creds['username'], rt.creds['password']) } });
      const token = typeof r.body === 'string' ? r.body.trim() : (r.body as { data?: { token?: string } })?.data?.token;
      if (!token) throw new ConnectorError('Wazuh did not return a token', 401);
      return { token, expiresInSec: 850 };               // Wazuh JWTs last 900 s by default
    });
    return http;
  },
  async test(rt) { const r = await rt.http.get('manager/info'); return { ok: true, detail: `Wazuh ${r.body?.data?.affected_items?.[0]?.version ?? 'server'} reachable` }; },
  async sync(rt): Promise<SyncResult> {
    const out = emptySync();
    for (let offset = 0, page = 0; page < MAX_PAGES; page++) {
      const r = await rt.http.get('agents', { query: { limit: 500, offset, select: 'id,name,ip,os.name,status,lastKeepAlive' } });
      const items = r.body?.data?.affected_items ?? [];
      for (const a of items) if (a?.name) out.assets.push({ type: a.id === '000' ? 'server' : 'endpoint', identifier: String(a.name), name: String(a.name), source: 'wazuh', tags: [`wazuh-agent:${a.id}`, a.os?.name, `status:${a.status}`].filter(Boolean), controls: a.status === 'active' ? ['edr'] : [] });
      offset += items.length; if (items.length < 500 || offset >= (r.body?.data?.total_affected_items ?? 0)) break;
    }
    const idx = rt.config.options['indexerUrl'] as string | undefined;
    if (idx) {
      const headers = { authorization: basic(rt.creds['indexerUsername'] ?? rt.creds['username'], rt.creds['indexerPassword'] ?? rt.creds['password']) };
      const since = rt.config.cursor ?? new Date(Date.now() - 86400000).toISOString();
      const al = await rt.http.post(`${idx.replace(/\/$/, '')}/wazuh-alerts-*/_search`, { absolute: true, noAuth: true, headers, json: { size: 500, sort: [{ timestamp: 'asc' }], query: { bool: { filter: [{ range: { 'rule.level': { gte: 7 } } }, { range: { timestamp: { gt: since } } }] } } } });
      let last = since;
      for (const h of al.body?.hits?.hits ?? []) {
        const s = h._source ?? {}, lvl = Number(s.rule?.level ?? 0), cves = [...String(JSON.stringify(s.data ?? {})).matchAll(/CVE-\d{4}-\d{4,}/gi)].map((m) => m[0].toUpperCase());
        out.signals.push({ source: 'wazuh', sourceId: String(h._id), kind: 'alert', title: String(s.rule?.description ?? 'Wazuh alert'), severity: lvl >= 12 ? 'critical' : lvl >= 10 ? 'high' : lvl >= 7 ? 'medium' : 'low', at: isoOr(s.timestamp), host: lc(s.agent?.name), ip: s.agent?.ip, user: s.data?.dstuser ?? s.data?.srcuser, cves: [...new Set(cves)], ips: [s.data?.srcip].filter(Boolean), raw: { ruleId: s.rule?.id, level: lvl, groups: s.rule?.groups } });
        if (s.timestamp && s.timestamp > last) last = s.timestamp;
      }
      out.cursor = last;
      const vs = await rt.http.post(`${idx.replace(/\/$/, '')}/wazuh-states-vulnerabilities-*/_search`, { absolute: true, noAuth: true, headers, json: { size: 1000, query: { match_all: {} } } }).catch(() => undefined);
      for (const h of vs?.body?.hits?.hits ?? []) {
        const s = h._source ?? {}, id = s.vulnerability?.id;
        if (typeof id === 'string' && /^CVE-/i.test(id) && s.agent?.name) out.vulns.push({ host: lc(s.agent.name)!, cve: id.toUpperCase(), title: `${id} in ${s.package?.name ?? 'package'}`, severity: sevFromText(s.vulnerability?.severity), cvss: Number(s.vulnerability?.score?.base) || undefined, evidence: [`wazuh vulnerability detector: ${s.package?.name} ${s.package?.version ?? ''}`.trim()] });
      }
    }
    return out;
  },
};

// ─────────────────────────── CrowdStrike Falcon ───────────────────────────
export const crowdstrike: Connector = {
  kind: 'crowdstrike', credentialFields: ['client_id', 'client_secret'],
  permissions: ['API client scope: Hosts: Read', 'API client scope: Alerts: Read'],
  prepare(rt) {
    const http = mkHttp(rt, [rt.creds['client_secret']]);
    http.tokenProvider = new TokenManager(async () => {
      const r = await http.post('oauth2/token', { noAuth: true, form: { client_id: rt.creds['client_id'], client_secret: rt.creds['client_secret'] } });
      if (!r.body?.access_token) throw new ConnectorError('CrowdStrike did not return an access token', 401);
      return { token: r.body.access_token, expiresInSec: Number(r.body.expires_in ?? 1799) };
    });
    return http;
  },
  async test(rt) { const r = await rt.http.get('devices/queries/devices/v1', { query: { limit: 1 } }); return { ok: true, detail: `Falcon API reachable (${r.body?.meta?.pagination?.total ?? '?'} hosts)` }; },
  async sync(rt) {
    const out = emptySync();
    for (let offset = 0, page = 0; page < MAX_PAGES; page++) {
      const ids: string[] = (await rt.http.get('devices/queries/devices/v1', { query: { limit: 500, offset } })).body?.resources ?? [];
      for (let i = 0; i < ids.length; i += 100) {
        const dev = (await rt.http.post('devices/entities/devices/v2', { json: { ids: ids.slice(i, i + 100) } })).body?.resources ?? [];
        for (const d of dev) if (d?.hostname) out.assets.push({ type: 'endpoint', identifier: String(d.hostname), name: String(d.hostname), source: 'crowdstrike', tags: [`cs:${d.device_id}`, d.platform_name, `status:${d.status}`].filter(Boolean), controls: ['edr'] });
      }
      offset += ids.length; if (ids.length < 500) break;
    }
    const since = rt.config.cursor ?? new Date(Date.now() - 86400000).toISOString();
    const aq = await rt.http.get('alerts/queries/alerts/v2', { query: { limit: 500, sort: 'created_timestamp.asc', filter: `created_timestamp:>'${since}'` } });
    const cids: string[] = aq.body?.resources ?? []; let last = since;
    for (let i = 0; i < cids.length; i += 100) for (const a of (await rt.http.post('alerts/entities/alerts/v2', { json: { composite_ids: cids.slice(i, i + 100) } })).body?.resources ?? []) {
      out.signals.push({ source: 'crowdstrike', sourceId: String(a.composite_id), kind: 'detection', title: String(a.name ?? a.description ?? 'Falcon alert'), severity: sevFromScore(Number(a.severity ?? 0)), at: isoOr(a.created_timestamp), host: lc(a.device?.hostname), ip: a.device?.local_ip, user: a.user_name, ips: [a.device?.external_ip].filter(Boolean), raw: { tactic: a.tactic, technique: a.technique, status: a.status } });
      if (a.created_timestamp > last) last = a.created_timestamp;
    }
    out.cursor = last; return out;
  },
};

// ─────────────────────────── Microsoft Defender ───────────────────────────
/** Microsoft Graph Security (alerts_v2) + Defender for Endpoint API (machines, machinesVulnerabilities), client-credentials with one token per audience. */
export const defender: Connector = {
  kind: 'defender', credentialFields: ['tenant_id', 'client_id', 'client_secret'],
  permissions: ['Microsoft Graph application permission: SecurityAlert.Read.All', 'Microsoft Graph application permission: SecurityIncident.Read.All', 'Defender for Endpoint API: Machine.Read.All', 'Defender for Endpoint API: Vulnerability.Read.All'],
  prepare(rt) {
    const http = mkHttp(rt, [rt.creds['client_secret']]);
    const login = String(rt.config.options['loginBase'] ?? 'https://login.microsoftonline.com'), graph = String(rt.config.options['graphBase'] ?? rt.config.baseUrl), mde = String(rt.config.options['mdeBase'] ?? 'https://api.securitycenter.microsoft.com');
    const mk = (scope: string) => new TokenManager(async () => {
      const r = await http.post(`${login.replace(/\/$/, '')}/${encodeURIComponent(rt.creds['tenant_id'])}/oauth2/v2.0/token`, { absolute: true, noAuth: true, form: { grant_type: 'client_credentials', client_id: rt.creds['client_id'], client_secret: rt.creds['client_secret'], scope } });
      if (!r.body?.access_token) throw new ConnectorError('Microsoft identity platform did not return an access token', 401);
      return { token: r.body.access_token, expiresInSec: Number(r.body.expires_in ?? 3599) };
    });
    const g = mk('https://graph.microsoft.com/.default'), m = mk('https://api.securitycenter.microsoft.com/.default');
    http.tokenSelector = (u) => (u.origin === new URL(mde).origin ? m : u.origin === new URL(graph).origin ? g : undefined);
    return http;
  },
  async test(rt) { const r = await rt.http.get('v1.0/security/alerts_v2', { query: { $top: 1 } }); return { ok: true, detail: `Microsoft Graph Security reachable (${(r.body?.value ?? []).length} sample alert)` }; },
  async sync(rt) {
    const out = emptySync(), mde = String(rt.config.options['mdeBase'] ?? 'https://api.securitycenter.microsoft.com').replace(/\/$/, '');
    const since = rt.config.cursor ?? new Date(Date.now() - 86400000).toISOString(); let last = since;
    let next: string | undefined = 'v1.0/security/alerts_v2'; let absolute = false;
    for (let page = 0; next && page < MAX_PAGES; page++) {
      const r: { body: any } = await rt.http.get(next, { absolute, query: absolute ? undefined : { $top: 200, $filter: `createdDateTime gt ${since}` } });
      for (const a of r.body?.value ?? []) {
        const ev: any[] = a.evidence ?? [], dev = ev.find((e) => /deviceEvidence/i.test(e['@odata.type'] ?? '')), ip = ev.find((e) => /ipEvidence/i.test(e['@odata.type'] ?? '')), usr = ev.find((e) => /userEvidence/i.test(e['@odata.type'] ?? ''));
        out.signals.push({ source: 'defender', sourceId: String(a.id), kind: 'alert', title: String(a.title ?? 'Defender alert'), severity: sevFromText(a.severity), at: isoOr(a.createdDateTime), host: lc(dev?.deviceDnsName)?.split('.')[0] ?? lc(dev?.deviceDnsName), ip: ip?.ipAddress, user: usr?.userAccount?.accountName, raw: { status: a.status, category: a.category, incidentId: a.incidentId } });
        if (a.createdDateTime > last) last = a.createdDateTime;
      }
      next = r.body?.['@odata.nextLink']; absolute = true;
    }
    out.cursor = last;
    for (const m of (await rt.http.get(`${mde}/api/machines`, { absolute: true }).catch(() => undefined))?.body?.value ?? [])
      if (m.computerDnsName) out.assets.push({ type: 'endpoint', identifier: String(m.computerDnsName), name: String(m.computerDnsName), source: 'defender', tags: [`mde:${m.id}`, m.osPlatform, `health:${m.healthStatus}`].filter(Boolean), controls: ['edr'] });
    for (const v of (await rt.http.get(`${mde}/api/vulnerabilities/machinesVulnerabilities`, { absolute: true, query: { $top: 1000 } }).catch(() => undefined))?.body?.value ?? [])
      if (v.cveId && v.fqdn) out.vulns.push({ host: String(v.fqdn).toLowerCase(), cve: String(v.cveId).toUpperCase(), title: `${v.cveId} in ${v.productName ?? 'software'}`, severity: sevFromText(v.severity), evidence: [`defender TVM: ${v.productName ?? ''} ${v.productVersion ?? ''}`.trim()] });
    return out;
  },
};
