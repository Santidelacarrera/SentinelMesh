import type { z } from 'zod';
import type { AssetSchema } from '../ctem/ctem.service';
import type { IdentityInput } from '../iam/iam.service';
import type { Severity } from '../store/models';
import type { ConnectorConfig, ConnectorKind } from '../store/enterprise.models';
import type { HttpClient } from './http';

export type AssetInput = z.infer<typeof AssetSchema>;
export interface SignalInput { source: string; sourceId: string; kind: 'alert' | 'detection' | 'incident' | 'event'; title: string; severity: Severity; at: string; host?: string; ip?: string; user?: string; cves?: string[]; domains?: string[]; ips?: string[]; raw?: unknown }
/** A vulnerability reported by a connector for a host. Never "confirmed": the source said so, nobody verified. */
export interface VulnInput { host: string; cve: string; title: string; severity?: Severity; cvss?: number; evidence: string[] }
export interface SyncResult { assets: AssetInput[]; identities: IdentityInput[]; signals: SignalInput[]; vulns: VulnInput[]; cursor?: string }
export const emptySync = (): SyncResult => ({ assets: [], identities: [], signals: [], vulns: [] });

export interface ConnectorRuntime { orgId: string; config: ConnectorConfig; creds: Record<string, string>; http: HttpClient; fetch?: typeof fetch; now?: () => number }
export interface Connector {
  readonly kind: ConnectorKind;
  /** Documented minimum (read-only) permissions this connector asks for. Surfaced in the UI and in docs/CONNECTORS.md. */
  readonly permissions: readonly string[];
  /** Fields the credentials JSON must contain. */
  readonly credentialFields: readonly string[];
  /** Builds the HTTP client wiring (base URL, token renewal) for this connector. */
  prepare(rt: Omit<ConnectorRuntime, 'http'>): HttpClient;
  test(rt: ConnectorRuntime): Promise<{ ok: boolean; detail: string }>;
  sync(rt: ConnectorRuntime): Promise<SyncResult>;
}

export const sevFromScore = (n: number): Severity => (n >= 90 ? 'critical' : n >= 70 ? 'high' : n >= 40 ? 'medium' : n > 0 ? 'low' : 'info');
export const sevFromText = (s: string | undefined): Severity => { const x = (s ?? '').toLowerCase(); return x.startsWith('crit') ? 'critical' : x.startsWith('high') ? 'high' : x.startsWith('med') ? 'medium' : x.startsWith('low') ? 'low' : 'info'; };
export const isoOr = (v: unknown, d = new Date().toISOString()) => { const t = typeof v === 'string' || typeof v === 'number' ? new Date(v) : undefined; return t && !Number.isNaN(t.getTime()) ? t.toISOString() : d; };
