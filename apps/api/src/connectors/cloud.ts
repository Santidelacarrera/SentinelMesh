import { SignJWT, importPKCS8 } from 'jose';
import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { S3Client, ListBucketsCommand, GetBucketPolicyStatusCommand } from '@aws-sdk/client-s3';
import { IAMClient, ListUsersCommand, ListMFADevicesCommand, ListAccessKeysCommand, ListAttachedUserPoliciesCommand } from '@aws-sdk/client-iam';
import { Connector, ConnectorRuntime, SyncResult, emptySync } from './types';
import { ConnectorError, HttpClient, TokenManager, connectorUrlPolicy } from './http';

const MAX_PAGES = 50;
const mkHttp = (rt: Omit<ConnectorRuntime, 'http'>, secrets: string[]) => new HttpClient({ baseUrl: rt.config.baseUrl, fetch: rt.fetch, rps: Number(rt.config.options['rps'] ?? 5), secrets, policy: connectorUrlPolicy() });

// ─────────────────────────── AWS (read-only, via the official SDK) ───────────────────────────
export interface AwsReader {
  caller(): Promise<string>;
  instances(): Promise<Array<{ id: string; name?: string; publicIp?: string; privateIp?: string; state?: string; tags: string[] }>>;
  buckets(): Promise<Array<{ name: string; public?: boolean }>>;
  users(): Promise<Array<{ name: string; arn: string; created?: Date; passwordLastUsed?: Date; mfa: boolean; keyAgeDays?: number; policies: string[] }>>;
}
export const AWS_READER = { make: (creds: Record<string, string>, endpoint?: string): AwsReader => sdkReader(creds, endpoint) as AwsReader };
function sdkReader(creds: Record<string, string>, endpoint?: string): AwsReader {
  const cfg = { region: creds['region'] ?? 'us-east-1', endpoint, credentials: { accessKeyId: creds['access_key_id'], secretAccessKey: creds['secret_access_key'], sessionToken: creds['session_token'] } };
  const ec2 = new EC2Client(cfg), s3 = new S3Client({ ...cfg, forcePathStyle: !!endpoint }), iam = new IAMClient(cfg);
  return {
    async caller() { await ec2.send(new DescribeInstancesCommand({ MaxResults: 5 })); return 'EC2 reachable'; },
    async instances() {
      const out: Awaited<ReturnType<AwsReader['instances']>> = []; let token: string | undefined;
      for (let p = 0; p < MAX_PAGES; p++) { const r = await ec2.send(new DescribeInstancesCommand({ NextToken: token })); for (const rs of r.Reservations ?? []) for (const i of rs.Instances ?? []) out.push({ id: i.InstanceId!, name: i.Tags?.find((t) => t.Key === 'Name')?.Value, publicIp: i.PublicIpAddress, privateIp: i.PrivateIpAddress, state: i.State?.Name, tags: (i.Tags ?? []).map((t) => `${t.Key}=${t.Value}`).slice(0, 10) }); token = r.NextToken; if (!token) break; }
      return out;
    },
    async buckets() {
      const r = await s3.send(new ListBucketsCommand({}));
      return Promise.all((r.Buckets ?? []).map(async (b) => ({ name: b.Name!, public: await s3.send(new GetBucketPolicyStatusCommand({ Bucket: b.Name! })).then((x) => x.PolicyStatus?.IsPublic, () => undefined) })));
    },
    async users() {
      const r = await iam.send(new ListUsersCommand({ MaxItems: 1000 }));
      return Promise.all((r.Users ?? []).map(async (u) => {
        const [m, k, p] = await Promise.all([iam.send(new ListMFADevicesCommand({ UserName: u.UserName })), iam.send(new ListAccessKeysCommand({ UserName: u.UserName })), iam.send(new ListAttachedUserPoliciesCommand({ UserName: u.UserName }))]);
        const ages = (k.AccessKeyMetadata ?? []).filter((x) => x.Status === 'Active' && x.CreateDate).map((x) => Math.floor((Date.now() - x.CreateDate!.getTime()) / 86400000));
        return { name: u.UserName!, arn: u.Arn!, created: u.CreateDate, passwordLastUsed: u.PasswordLastUsed, mfa: (m.MFADevices ?? []).length > 0, keyAgeDays: ages.length ? Math.max(...ages) : undefined, policies: (p.AttachedPolicies ?? []).map((x) => x.PolicyName!) };
      }));
    },
  };
}
export const aws: Connector & { reader?: (creds: Record<string, string>, endpoint?: string) => AwsReader } = {
  kind: 'aws', credentialFields: ['access_key_id', 'secret_access_key'],
  permissions: ['ec2:DescribeInstances', 's3:ListAllMyBuckets', 's3:GetBucketPolicyStatus', 'iam:ListUsers', 'iam:ListMFADevices', 'iam:ListAccessKeys', 'iam:ListAttachedUserPolicies (all read-only; attach the managed policy SecurityAudit or ViewOnlyAccess)'],
  prepare(rt) { return new HttpClient({ baseUrl: rt.config.baseUrl || 'https://aws.amazon.com', fetch: rt.fetch }); },     // unused: the SDK does its own transport
  async test(rt) { return { ok: true, detail: await aws.reader!(rt.creds, rt.config.baseUrl.includes('amazonaws.com') ? undefined : rt.config.baseUrl).caller() }; },
  async sync(rt): Promise<SyncResult> {
    const out = emptySync(), rd = aws.reader!(rt.creds, rt.config.baseUrl.includes('amazonaws.com') ? undefined : rt.config.baseUrl);
    for (const i of await rd.instances()) if (i.state !== 'terminated') out.assets.push({ type: 'server', identifier: i.id, name: i.name ?? i.id, source: 'aws', internetFacing: !!i.publicIp, tags: [...i.tags, i.publicIp ? `public-ip:${i.publicIp}` : ''].filter(Boolean) });
    for (const b of await rd.buckets()) out.assets.push({ type: 'cloud_service', identifier: `s3:${b.name}`, name: `s3://${b.name}`, source: 'aws', internetFacing: b.public === true, tags: [b.public === undefined ? 'public-status:unknown' : `public:${b.public}`] });
    for (const u of await rd.users()) out.identities.push({ kind: 'human', name: u.name, provider: 'aws', externalId: u.arn, status: 'active', mfaEnabled: u.mfa, lastActivityAt: u.passwordLastUsed?.toISOString(), credentialAgeDays: u.keyAgeDays, entitlements: u.policies, authMethods: [u.mfa ? 'mfa' : 'password', ...(u.keyAgeDays !== undefined ? ['static_api_key'] : [])], assetIds: [] });
    return out;
  },
};
aws.reader = (c, e) => AWS_READER.make(c, e);

// ─────────────────────────── Azure (Resource Manager REST, client credentials) ───────────────────────────
export const azure: Connector = {
  kind: 'azure', credentialFields: ['tenant_id', 'client_id', 'client_secret', 'subscription_id'],
  permissions: ['Azure RBAC role "Reader" on the subscription', 'Azure RBAC role "Security Reader" on the subscription'],
  prepare(rt) {
    const http = mkHttp(rt, [rt.creds['client_secret']]), login = String(rt.config.options['loginBase'] ?? 'https://login.microsoftonline.com');
    http.tokenProvider = new TokenManager(async () => {
      const r = await http.post(`${login.replace(/\/$/, '')}/${encodeURIComponent(rt.creds['tenant_id'])}/oauth2/v2.0/token`, { absolute: true, noAuth: true, form: { grant_type: 'client_credentials', client_id: rt.creds['client_id'], client_secret: rt.creds['client_secret'], scope: 'https://management.azure.com/.default' } });
      if (!r.body?.access_token) throw new ConnectorError('Microsoft identity platform did not return an access token', 401);
      return { token: r.body.access_token, expiresInSec: Number(r.body.expires_in ?? 3599) };
    });
    return http;
  },
  async test(rt) { const r = await rt.http.get(`subscriptions/${encodeURIComponent(rt.creds['subscription_id'])}`, { query: { 'api-version': '2022-12-01' } }); return { ok: true, detail: `subscription "${r.body?.displayName ?? rt.creds['subscription_id']}" reachable` }; },
  async sync(rt) {
    const out = emptySync(), sub = encodeURIComponent(rt.creds['subscription_id']);
    const list = async (path: string, v: string) => { const all: any[] = []; let next: string | undefined = path, abs = false; for (let p = 0; next && p < MAX_PAGES; p++) { const r: { body: any } = await rt.http.get(next, { absolute: abs, query: abs ? undefined : { 'api-version': v } }); all.push(...(r.body?.value ?? [])); next = r.body?.nextLink; abs = true; } return all; };
    const pips = await list(`subscriptions/${sub}/providers/Microsoft.Network/publicIPAddresses`, '2023-09-01');
    const publicNics = new Set(pips.map((x) => String(x.properties?.ipConfiguration?.id ?? '').split('/ipConfigurations/')[0].toLowerCase()).filter(Boolean));
    for (const vm of await list(`subscriptions/${sub}/providers/Microsoft.Compute/virtualMachines`, '2024-03-01')) {
      const nics: string[] = (vm.properties?.networkProfile?.networkInterfaces ?? []).map((n: { id: string }) => n.id.toLowerCase());
      out.assets.push({ type: 'server', identifier: String(vm.id).toLowerCase(), name: vm.name, source: 'azure', internetFacing: nics.some((n) => publicNics.has(n)), tags: [`location:${vm.location}`, ...Object.entries(vm.tags ?? {}).slice(0, 8).map(([k, v]) => `${k}=${v}`)] });
    }
    for (const sa of await list(`subscriptions/${sub}/providers/Microsoft.Storage/storageAccounts`, '2023-01-01'))
      out.assets.push({ type: 'cloud_service', identifier: String(sa.id).toLowerCase(), name: sa.name, source: 'azure', internetFacing: sa.properties?.allowBlobPublicAccess === true, tags: [`blob-public-access:${sa.properties?.allowBlobPublicAccess ?? 'unknown'}`] });
    return out;
  },
};

// ─────────────────────────── Google Cloud (Cloud Asset API, service-account JWT) ───────────────────────────
export const gcp: Connector = {
  kind: 'gcp', credentialFields: ['client_email', 'private_key', 'project_id'],
  permissions: ['roles/cloudasset.viewer', 'roles/securitycenter.findingsViewer (optional, for Security Command Center findings)'],
  prepare(rt) {
    const http = mkHttp(rt, [rt.creds['private_key']]), tokenUri = String(rt.config.options['tokenUri'] ?? 'https://oauth2.googleapis.com/token');
    http.tokenProvider = new TokenManager(async () => {
      const key = await importPKCS8(rt.creds['private_key'].replace(/\\n/g, '\n'), 'RS256');
      const assertion = await new SignJWT({ scope: 'https://www.googleapis.com/auth/cloud-platform' }).setProtectedHeader({ alg: 'RS256', typ: 'JWT' }).setIssuer(rt.creds['client_email']).setSubject(rt.creds['client_email']).setAudience(tokenUri).setIssuedAt().setExpirationTime('55m').sign(key);
      const r = await http.post(tokenUri, { absolute: true, noAuth: true, form: { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion } });
      if (!r.body?.access_token) throw new ConnectorError('Google did not return an access token', 401);
      return { token: r.body.access_token, expiresInSec: Number(r.body.expires_in ?? 3599) };
    });
    return http;
  },
  async test(rt) { await rt.http.get(`v1/projects/${encodeURIComponent(rt.creds['project_id'])}/assets`, { query: { contentType: 'RESOURCE', pageSize: 1, assetTypes: 'compute.googleapis.com/Instance' } }); return { ok: true, detail: `Cloud Asset API reachable for project ${rt.creds['project_id']}` }; },
  async sync(rt) {
    const out = emptySync(), project = encodeURIComponent(rt.creds['project_id']); let token: string | undefined;
    for (let p = 0; p < MAX_PAGES; p++) {
      const r: { body: any } = await rt.http.get(`v1/projects/${project}/assets`, { query: { contentType: 'RESOURCE', pageSize: 500, pageToken: token, assetTypes: 'compute.googleapis.com/Instance' } });
      for (const a of r.body?.assets ?? []) {
        const d = a.resource?.data ?? {}, external = (d.networkInterfaces ?? []).some((n: any) => (n.accessConfigs ?? []).length > 0);
        out.assets.push({ type: 'server', identifier: String(a.name).toLowerCase(), name: d.name ?? a.name, source: 'gcp', internetFacing: external, tags: [`zone:${String(d.zone ?? '').split('/').pop()}`, `status:${d.status}`] });
      }
      token = r.body?.nextPageToken; if (!token) break;
    }
    if (rt.config.options['securityCenter'] === true) {
      const f = await rt.http.get(`https://securitycenter.googleapis.com/v2/projects/${project}/sources/-/findings`, { absolute: true, query: { pageSize: 200, filter: 'state="ACTIVE"' } }).catch(() => undefined);
      for (const x of f?.body?.listFindingsResults ?? []) { const fd = x.finding ?? {}; out.signals.push({ source: 'gcp-scc', sourceId: String(fd.name), kind: 'alert', title: String(fd.category ?? 'SCC finding'), severity: ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' } as const)[fd.severity as 'LOW'] ?? 'info', at: fd.createTime ?? new Date().toISOString(), host: String(fd.resourceName ?? '').split('/').pop()?.toLowerCase() }); }
    }
    return out;
  },
};
