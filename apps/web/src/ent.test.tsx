import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ReactNode } from 'react';
import { SessionCtx } from './api';
import { Cases, Ctem, Executive, Iam, Integrations, Reports, Soar } from './ent';
import type { Role } from './types';

/** Renders a view with a fake API: the console must show what the API says, with honest states and role-aware controls. */
const withApi = (data: Record<string, unknown>, role: Role = 'admin'): ReactNode => {
  const api = { get: async (p: string) => { const k = Object.keys(data).find((x) => p.startsWith(x)); if (!k) throw new Error(`unexpected GET ${p}`); return data[k]; }, post: async () => ({}), download: async () => undefined } as never;
  return { api, me: { userId: 'u', orgId: 'o', role, email: 'a@b.test' }, signOut: () => {}, refreshCounts: () => {} } as never;
};
const ui = (session: unknown, node: ReactNode) => <SessionCtx.Provider value={session as never}>{node}</SessionCtx.Provider>;
const exec = (o: object = {}) => ({ hasData: true, plan: { plan: 'business', features: [] }, risk: { score: 62, level: 'high', factors: [{ name: 'Top open vulnerabilities', points: 40, max: 50 }] }, assets: { total: 3, internetFacing: 1, stale: 0, unverifiedOwnership: 3 }, vulnerabilities: { open: 4, immediate: 1, critical: 1, kev: 1, overdue: 0 },
  cases: { active: 2, bySeverity: {}, probableCorrelations: 1 }, identities: { total: 5, privileged: 2, inActiveCases: 0, riskyConfirmed: 1 }, exposures: { open: 1, confirmed: 1, suspected: 0 }, priorities: [], approvalsPending: 1,
  trend: { series: [{ date: '2026-11-01', vulnerabilities: 1, cases: 0, signals: 2 }] }, integrations: { connectors: { total: 2, byStatus: { connected: 1, error: 1 }, failing: [{ name: 'Wazuh', kind: 'wazuh', error: 'HTTP 401' }] }, notificationChannels: [] }, limitations: ['Counts reflect only ingested data.'], ...o });

describe('executive view', () => {
  it('shows a dash instead of inventing a score when there is no data', async () => {
    render(ui(withApi({ '/dashboard/executive': exec({ hasData: false, risk: { score: null, level: 'no data', factors: [] }, assets: { total: 0, internetFacing: 0, stale: 0, unverifiedOwnership: 0 } }) }), <Executive />));
    expect(await screen.findByText('no data')).toBeTruthy(); expect(screen.getAllByText('—').length).toBeGreaterThan(0);
  });
  it('shows the score, why, and failing integrations with their error', async () => {
    render(ui(withApi({ '/dashboard/executive': exec() }), <Executive />));
    expect(await screen.findByText('62')).toBeTruthy(); expect(screen.getByText('Top open vulnerabilities')).toBeTruthy(); expect(screen.getByText(/Wazuh: HTTP 401/)).toBeTruthy(); expect(screen.getByText('Con errores')).toBeTruthy();
  });
});

describe('integrations view', () => {
  const conns = [
    { id: 'c1', kind: 'wazuh', name: 'Wazuh prod', enabled: true, baseUrl: 'https://w', status: 'not_configured', verification: 'implemented', hasCredentials: false, requiredPermissions: ['agent:read'], activity: [] },
    { id: 'c2', kind: 'crowdstrike', name: 'Falcon', enabled: true, baseUrl: 'https://f', status: 'connected', verification: 'connected', hasCredentials: true, lastSyncAt: new Date().toISOString(), requiredPermissions: [], activity: [] },
    { id: 'c3', kind: 'okta', name: 'Okta', enabled: true, baseUrl: 'http://127.0.0.1', status: 'error', verification: 'simulated', hasCredentials: true, lastError: 'HTTP 401 from okta', requiredPermissions: [], activity: [] },
  ];
  it('shows the real state and verification of every connector — never "connected" without proof', async () => {
    render(ui(withApi({ '/connectors': conns, '/notifications/channels': [] }), <Integrations />));
    expect(await screen.findByText('No configurada')).toBeTruthy(); expect(screen.getByText('Conectada')).toBeTruthy(); expect(screen.getByText('Con errores')).toBeTruthy();
    expect(screen.getByText(/Implementada, sin verificar contra un servicio real/)).toBeTruthy(); expect(screen.getByText(/Simulada \(endpoint local/)).toBeTruthy(); expect(screen.getByText('HTTP 401 from okta')).toBeTruthy();
  });
  it('offers test/sync only to administrators, and not for connectors without credentials', async () => {
    const { unmount } = render(ui(withApi({ '/connectors': conns, '/notifications/channels': [] }, 'viewer'), <Integrations />));
    await screen.findByText('No configurada'); expect(screen.queryAllByText('Sincronizar')).toHaveLength(0); unmount();
    render(ui(withApi({ '/connectors': conns, '/notifications/channels': [] }, 'admin'), <Integrations />));
    await screen.findByText('No configurada'); const sync = screen.getAllByText('Sincronizar') as HTMLButtonElement[];
    expect(sync).toHaveLength(3); expect(sync[0].disabled).toBe(true); expect(sync[1].disabled).toBe(false);
  });
});

describe('other views: states and permissions', () => {
  it('SOAR: approvals can only be signed by approvers; the exact parameters are shown', async () => {
    const ap = [{ approvalId: 'a1', runId: 'r', playbook: 'endpoint-compromised', action: 'propose_endpoint_isolation', params: { target: 'web-01' }, riskLevel: 'high', requestedBy: 'system', requestedAt: new Date().toISOString(), planHash: 'x' }];
    const data = { '/soar/playbooks': [], '/soar/runs': [], '/soar/approvals': ap, '/soar/automation': { ceiling: 'ASSISTED', automatedEnabled: false, allowedAutoActions: [], maxActionsPerHour: 10, killSwitch: false } };
    const { unmount } = render(ui(withApi(data, 'analyst'), <Soar />));
    expect(await screen.findByText(/propose_endpoint_isolation/)).toBeTruthy(); expect(screen.getByText(/"target":"web-01"/)).toBeTruthy();
    expect((screen.getByRole('button', { name: /Mantén para aprobar/ }) as HTMLButtonElement).disabled).toBe(true); unmount();
    render(ui(withApi(data, 'approver'), <Soar />));
    await screen.findByText(/propose_endpoint_isolation/); expect((screen.getByRole('button', { name: /Mantén para aprobar/ }) as HTMLButtonElement).disabled).toBe(false);
  });
  it('empty states explain what to do instead of showing blank tables', async () => {
    render(ui(withApi({ '/cases': { total: 0, items: [] } }), <Cases />));
    expect(await screen.findByText('Sin casos')).toBeTruthy();
  });
  it('IAM marks unverifiable data as unknown, not as safe', async () => {
    const ident = { id: 'i1', kind: 'human', name: 'Ann', provider: 'entra', privileged: true, status: 'active', entitlements: [] };
    render(ui(withApi({ '/iam/identities': { total: 1, items: [ident] }, '/iam/summary': { total: 1, human: 1, service: 0, privileged: 1, inactive: 0, unverified: 2, risksBySeverity: { critical: 0, high: 0 } }, '/iam/risks': [] }), <Iam />));
    expect(await screen.findByText('desconocido')).toBeTruthy(); expect(screen.getByText('desconocida')).toBeTruthy();
  });
  it('CTEM vulnerabilities show n/d for missing scores and the reason for each priority', async () => {
    const v = { id: 'v1', title: 'x', cve: 'CVE-2024-1001', severity: 'high', status: 'open', confidence: 'suspected', source: 'wazuh', priority: { level: 'high', score: 60, explanation: 'Priority HIGH (60/100)' } };
    render(ui(withApi({ '/vulns': { total: 1, items: [v] } }), <Ctem />));
    expect(await screen.findByText('CVE-2024-1001')).toBeTruthy(); expect(screen.getByText(/n\/d \/ n\/d/)).toBeTruthy(); expect(screen.getByText('Priority HIGH (60/100)')).toBeTruthy();
  });
  it('reports: viewers cannot generate, anyone can list', async () => {
    render(ui(withApi({ '/reports': [] }, 'viewer'), <Reports />));
    expect(await screen.findByText('Aún no hay informes.')).toBeTruthy(); expect(screen.queryByText('Generar PDF')).toBeNull();
  });
});

describe('admin view', () => {
  it('is closed to non-administrators and shows users with safe self-protection for admins', async () => {
    const { Admin } = await import('./admin');
    const { unmount } = render(ui(withApi({ '/plan': { plan: 'business', features: [], limits: {} } }, 'analyst'), <Admin />));
    expect(await screen.findByText('Solo administradores')).toBeTruthy(); unmount();
    const users = [{ id: 'u', email: 'a@b.test', role: 'admin', status: 'active', mfaEnabled: true, createdAt: '' }, { id: 'v', email: 'v@b.test', role: 'viewer', status: 'active', mfaEnabled: false, createdAt: '' }];
    render(ui(withApi({ '/users': users, '/roles': [], '/plan': { plan: 'enterprise', features: ['soar'], limits: { assets: null } }, '/ops/health': { status: 'ok', issues: [], queue: { waiting: 0, failed: 0 }, auditChain: { ok: true } } }, 'admin'), <Admin />));
    expect(await screen.findByText('v@b.test')).toBeTruthy();
    const off = screen.getAllByText('Deshabilitar') as HTMLButtonElement[]; expect(off[0].disabled).toBe(true); expect(off[1].disabled).toBe(false);   // you cannot disable yourself
  });
});
