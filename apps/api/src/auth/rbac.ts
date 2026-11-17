import type { SecOpsRole } from '../store/models';

/**
 * Permission catalogue. Roles are bundles of permissions; custom roles (per organisation) add permissions on top of `viewer`
 * (least privilege: a custom role never inherits more than it lists). `platform:*` exists only for the `platform_admin` role,
 * which can only be held by users of the platform organisation.
 */
export const PLATFORM_ORG = 'org_platform';

const READ = ['assets:read', 'vulns:read', 'exposures:read', 'paths:read', 'identities:read', 'signals:read', 'cases:read', 'evidence:read', 'playbooks:read', 'runs:read',
  'connectors:read', 'channels:read', 'reports:read', 'dashboard:read', 'audit:read', 'findings:read', 'approvals:read', 'ai:use'] as const;
const WRITE = ['assets:write', 'vulns:write', 'intel:write', 'exposures:write', 'identities:write', 'signals:write', 'cases:write', 'evidence:write', 'playbooks:write', 'runs:trigger',
  'findings:write', 'reports:generate', 'connectors:sync', 'evidence:export', 'assets:verify'] as const;
const APPROVE = ['approvals:decide', 'runs:approve'] as const;
const ADMIN = ['users:manage', 'roles:manage', 'connectors:manage', 'channels:manage', 'settings:manage', 'automation:manage', 'privacy:manage', 'playbooks:enable', 'sessions:manage'] as const;

export const BASE_PERMISSIONS: Record<SecOpsRole, ReadonlySet<string>> = {
  viewer: new Set(READ),
  analyst: new Set([...READ, ...WRITE]),
  approver: new Set([...READ, ...WRITE, ...APPROVE]),
  admin: new Set([...READ, ...WRITE, ...APPROVE, ...ADMIN]),
  platform_admin: new Set([...READ, ...WRITE, ...APPROVE, ...ADMIN, 'platform:manage']),
};
export const ALL_PERMISSIONS: ReadonlySet<string> = new Set(BASE_PERMISSIONS.platform_admin);
export const isRole = (r: string): r is SecOpsRole => r in BASE_PERMISSIONS;

export function permissionsFor(role: string, custom: Array<{ permissions: string[] }> = []): Set<string> {
  const out = new Set(isRole(role) ? BASE_PERMISSIONS[role] : BASE_PERMISSIONS.viewer);
  for (const c of custom) for (const p of c.permissions) if (ALL_PERMISSIONS.has(p) && p !== 'platform:manage') out.add(p);
  return out;
}
