import { SignJWT, importPKCS8 } from 'jose';
import type { IdentityInput } from '../iam/iam.service';
import { Connector, ConnectorRuntime, SyncResult, emptySync } from './types';
import { ConnectorError, HttpClient, TokenManager, connectorUrlPolicy } from './http';

const MAX_PAGES = 50;
const mkHttp = (rt: Omit<ConnectorRuntime, 'http'>, secrets: string[]) => new HttpClient({ baseUrl: rt.config.baseUrl, fetch: rt.fetch, rps: Number(rt.config.options['rps'] ?? 5), secrets, policy: connectorUrlPolicy() });
const ident = (i: Omit<IdentityInput, 'authMethods' | 'assetIds' | 'entitlements' | 'status'> & Partial<IdentityInput>): IdentityInput => ({ authMethods: [], assetIds: [], entitlements: [], status: 'active', ...i });

// ─────────────────────────── Microsoft Entra ID (Graph) ───────────────────────────
export const entra: Connector = {
  kind: 'entra', credentialFields: ['tenant_id', 'client_id', 'client_secret'],
  permissions: ['Microsoft Graph application permission: User.Read.All', 'Microsoft Graph application permission: RoleManagement.Read.Directory', 'Microsoft Graph application permission: AuditLog.Read.All (sign-in activity, MFA registration)'],
  prepare(rt) {
    const http = mkHttp(rt, [rt.creds['client_secret']]), login = String(rt.config.options['loginBase'] ?? 'https://login.microsoftonline.com');
    http.tokenProvider = new TokenManager(async () => {
      const r = await http.post(`${login.replace(/\/$/, '')}/${encodeURIComponent(rt.creds['tenant_id'])}/oauth2/v2.0/token`, { absolute: true, noAuth: true, form: { grant_type: 'client_credentials', client_id: rt.creds['client_id'], client_secret: rt.creds['client_secret'], scope: 'https://graph.microsoft.com/.default' } });
      if (!r.body?.access_token) throw new ConnectorError('Microsoft identity platform did not return an access token', 401);
      return { token: r.body.access_token, expiresInSec: Number(r.body.expires_in ?? 3599) };
    });
    return http;
  },
  async test(rt) { const r = await rt.http.get('v1.0/organization', { query: { $select: 'displayName' } }); return { ok: true, detail: `tenant "${r.body?.value?.[0]?.displayName ?? 'unknown'}" reachable` }; },
  async sync(rt) {
    const out = emptySync(), roles = new Map<string, string[]>(), mfa = new Map<string, boolean>();
    for (const role of (await rt.http.get('v1.0/directoryRoles')).body?.value ?? [])
      for (const m of (await rt.http.get(`v1.0/directoryRoles/${encodeURIComponent(role.id)}/members`, { query: { $select: 'id' } }).catch(() => undefined))?.body?.value ?? []) roles.set(m.id, [...(roles.get(m.id) ?? []), role.displayName]);
    let nxt: string | undefined = 'v1.0/reports/authenticationMethods/userRegistrationDetails', abs = false;
    for (let p = 0; nxt && p < MAX_PAGES; p++) { const r: { body: any } | undefined = await rt.http.get(nxt, { absolute: abs, query: abs ? undefined : { $top: 500 } }).catch(() => undefined); for (const d of r?.body?.value ?? []) mfa.set(d.id, !!d.isMfaRegistered); nxt = r?.body?.['@odata.nextLink']; abs = true; }
    nxt = 'v1.0/users'; abs = false;
    for (let p = 0; nxt && p < MAX_PAGES; p++) {
      const r: { body: any } = await rt.http.get(nxt, { absolute: abs, query: abs ? undefined : { $select: 'id,displayName,userPrincipalName,accountEnabled,userType,signInActivity', $top: 200 } });
      for (const u of r.body?.value ?? []) out.identities.push(ident({ kind: 'human', name: u.displayName ?? u.userPrincipalName, email: u.userPrincipalName?.includes('@') ? u.userPrincipalName : undefined, provider: 'entra', externalId: String(u.id), status: u.accountEnabled === false ? 'disabled' : 'active',
        entitlements: roles.get(u.id) ?? [], mfaEnabled: mfa.get(u.id), lastActivityAt: u.signInActivity?.lastSuccessfulSignInDateTime ?? u.signInActivity?.lastSignInDateTime ?? undefined, authMethods: mfa.get(u.id) ? ['mfa'] : mfa.has(u.id) ? ['password'] : [] }));
      nxt = r.body?.['@odata.nextLink']; abs = true;
    }
    return out;
  },
};

// ─────────────────────────── Okta ───────────────────────────
const nextLink = (h: Headers) => /<([^>]+)>;\s*rel="next"/.exec(h.get('link') ?? '')?.[1];
export const okta: Connector = {
  kind: 'okta', credentialFields: ['api_token'],
  permissions: ['Okta API token of a read-only administrator (okta.users.read, okta.roles.read)'],
  prepare(rt) { return mkHttp(rt, [rt.creds['api_token']]); },
  async test(rt) { const r = await rt.http.get('api/v1/users', { query: { limit: 1 }, headers: { authorization: `SSWS ${rt.creds['api_token']}` } }); return { ok: true, detail: `Okta reachable (${Array.isArray(r.body) ? r.body.length : 0} sample user)` }; },
  async sync(rt): Promise<SyncResult> {
    const out = emptySync(), h = { authorization: `SSWS ${rt.creds['api_token']}` }, cap = Number(rt.config.options['maxLookups'] ?? 500);
    let url: string | undefined = 'api/v1/users', abs = false, lookups = 0;
    for (let p = 0; url && p < MAX_PAGES; p++) {
      const r: { body: any; headers: Headers } = await rt.http.get(url, { absolute: abs, query: abs ? undefined : { limit: 200 }, headers: h });
      for (const u of Array.isArray(r.body) ? r.body : []) {
        const active = ['ACTIVE', 'RECOVERY', 'PASSWORD_EXPIRED', 'PROVISIONED'].includes(u.status);
        let mfaEnabled: boolean | undefined, roles: string[] = [];
        if (active && lookups < cap) {
          lookups++;
          const f = await rt.http.get(`api/v1/users/${encodeURIComponent(u.id)}/factors`, { headers: h }).catch(() => undefined);
          if (f) mfaEnabled = (Array.isArray(f.body) ? f.body : []).some((x: { status?: string }) => x.status === 'ACTIVE');
          const rr = await rt.http.get(`api/v1/users/${encodeURIComponent(u.id)}/roles`, { headers: h }).catch(() => undefined);
          roles = (Array.isArray(rr?.body) ? rr!.body : []).map((x: { type?: string }) => String(x.type ?? '').replace(/_/g, ' ')).filter(Boolean);
        }
        out.identities.push(ident({ kind: 'human', name: u.profile?.displayName ?? u.profile?.login, email: u.profile?.email, provider: 'okta', externalId: String(u.id), status: active ? 'active' : 'disabled', entitlements: roles, mfaEnabled, lastActivityAt: u.lastLogin ?? undefined, authMethods: mfaEnabled ? ['mfa'] : [],
          privileged: roles.some((x) => /^(super|org) admin$/i.test(x)) || undefined }));
      }
      url = nextLink(r.headers); abs = true;
    }
    return out;
  },
};

// ─────────────────────────── Google Workspace ───────────────────────────
export const googleWorkspace: Connector = {
  kind: 'google_workspace', credentialFields: ['client_email', 'private_key', 'subject'],
  permissions: ['Service account with domain-wide delegation for scope https://www.googleapis.com/auth/admin.directory.user.readonly', 'subject: an administrator the service account impersonates (read-only use)'],
  prepare(rt) {
    const http = mkHttp(rt, [rt.creds['private_key']]), tokenUri = String(rt.config.options['tokenUri'] ?? 'https://oauth2.googleapis.com/token');
    http.tokenProvider = new TokenManager(async () => {
      const key = await importPKCS8(rt.creds['private_key'].replace(/\\n/g, '\n'), 'RS256');
      const assertion = await new SignJWT({ scope: 'https://www.googleapis.com/auth/admin.directory.user.readonly' }).setProtectedHeader({ alg: 'RS256', typ: 'JWT' }).setIssuer(rt.creds['client_email']).setSubject(rt.creds['subject']).setAudience(tokenUri).setIssuedAt().setExpirationTime('55m').sign(key);
      const r = await http.post(tokenUri, { absolute: true, noAuth: true, form: { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion } });
      if (!r.body?.access_token) throw new ConnectorError('Google did not return an access token', 401);
      return { token: r.body.access_token, expiresInSec: Number(r.body.expires_in ?? 3599) };
    });
    return http;
  },
  async test(rt) { const r = await rt.http.get('admin/directory/v1/users', { query: { customer: 'my_customer', maxResults: 1 } }); return { ok: true, detail: `Directory API reachable (${(r.body?.users ?? []).length} sample user)` }; },
  async sync(rt) {
    const out = emptySync(); let token: string | undefined;
    for (let p = 0; p < MAX_PAGES; p++) {
      const r: { body: any } = await rt.http.get('admin/directory/v1/users', { query: { customer: 'my_customer', maxResults: 500, pageToken: token } });
      for (const u of r.body?.users ?? []) {
        const never = !u.lastLoginTime || String(u.lastLoginTime).startsWith('1970');
        out.identities.push(ident({ kind: 'human', name: u.name?.fullName ?? u.primaryEmail, email: u.primaryEmail, provider: 'google_workspace', externalId: String(u.id), status: u.suspended ? 'disabled' : 'active', mfaEnabled: u.isEnrolledIn2Sv,
          entitlements: [u.isAdmin ? 'Super Admin' : '', u.isDelegatedAdmin ? 'Delegated Admin' : ''].filter(Boolean), lastActivityAt: never ? undefined : u.lastLoginTime, authMethods: u.isEnrolledIn2Sv ? ['mfa'] : ['password'] }));
      }
      token = r.body?.nextPageToken; if (!token) break;
    }
    return out;
  },
};
