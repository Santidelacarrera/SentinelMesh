/**
 * Parsers for public vulnerability-intelligence feeds. The platform never fetches or fabricates scores: an operator (or a scheduled job
 * the operator controls) supplies the downloaded feed and only fields present in it are recorded.
 *  - NVD CVE API 2.0 JSON   → cvss, cwe, description
 *  - CISA KEV catalogue JSON → kev, due date
 *  - FIRST EPSS (JSON `data[]` or CSV `cve,epss,percentile`) → epss
 */
export interface IntelPatch { cve: string; cvss?: { score: number; vector?: string; version?: string }; cwe?: string; description?: string; kev?: boolean; kevDueDate?: string; epss?: { score: number; percentile?: number; asOf?: string } }
const CVE = /^CVE-\d{4}-\d{4,}$/i;
const num = (v: unknown) => { const n = typeof v === 'string' ? Number(v) : v; return typeof n === 'number' && Number.isFinite(n) ? n : undefined; };

export function parseNvd(payload: unknown): IntelPatch[] {
  const items = (payload as { vulnerabilities?: Array<{ cve?: any }> })?.vulnerabilities;
  if (!Array.isArray(items)) throw new Error('not an NVD 2.0 document (missing vulnerabilities[])');
  const out: IntelPatch[] = [];
  for (const it of items) {
    const c = it?.cve; if (!c || typeof c.id !== 'string' || !CVE.test(c.id)) continue;
    const m = c.metrics ?? {}, cm = (m.cvssMetricV40 ?? m.cvssMetricV31 ?? m.cvssMetricV30 ?? m.cvssMetricV2 ?? [])[0]?.cvssData;
    const score = num(cm?.baseScore);
    out.push({
      cve: c.id.toUpperCase(),
      ...(score !== undefined && score >= 0 && score <= 10 ? { cvss: { score, vector: typeof cm.vectorString === 'string' ? cm.vectorString : undefined, version: typeof cm.version === 'string' ? cm.version : undefined } } : {}),
      cwe: (c.weaknesses ?? []).flatMap((w: any) => w.description ?? []).map((d: any) => d.value).find((v: unknown) => typeof v === 'string' && /^CWE-\d+$/.test(v)),
      description: (c.descriptions ?? []).find((d: any) => d.lang === 'en')?.value?.slice(0, 2000),
    });
  }
  return out;
}

export function parseKev(payload: unknown): IntelPatch[] {
  const items = (payload as { vulnerabilities?: Array<{ cveID?: string; dueDate?: string }> })?.vulnerabilities;
  if (!Array.isArray(items) || !items.some((i) => i && 'cveID' in i)) throw new Error('not a CISA KEV catalogue (missing vulnerabilities[].cveID)');
  return items.filter((i) => typeof i?.cveID === 'string' && CVE.test(i.cveID)).map((i) => ({ cve: i.cveID!.toUpperCase(), kev: true, ...(typeof i.dueDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(i.dueDate) ? { kevDueDate: i.dueDate } : {}) }));
}

export function parseEpss(payload: unknown): IntelPatch[] {
  const rows: Array<{ cve: string; epss: unknown; percentile?: unknown; date?: unknown }> = [];
  if (typeof payload === 'string') {
    for (const line of payload.split(/\r?\n/)) {
      if (!line || line.startsWith('#') || /^cve,/i.test(line)) continue;
      const [cve, epss, percentile] = line.split(',');
      rows.push({ cve, epss, percentile });
    }
  } else if (Array.isArray((payload as { data?: unknown })?.data)) rows.push(...(payload as { data: typeof rows }).data);
  else throw new Error('not an EPSS document (expected CSV text or {data: [...]})');
  const out: IntelPatch[] = [];
  for (const r of rows) {
    const s = num(r.epss);
    if (typeof r.cve === 'string' && CVE.test(r.cve) && s !== undefined && s >= 0 && s <= 1) out.push({ cve: r.cve.toUpperCase(), epss: { score: s, percentile: num(r.percentile), asOf: typeof r.date === 'string' ? r.date : undefined } });
  }
  return out;
}
export const INTEL_PARSERS = { nvd: parseNvd, kev: parseKev, epss: parseEpss } as const;
