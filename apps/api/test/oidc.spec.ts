import { SignJWT, exportJWK, generateKeyPair, createLocalJWKSet } from 'jose';
import request from 'supertest';
import { boot } from './helpers';
import { AuthService, OidcVerifier } from '../src/auth/auth';

const ISS = 'https://idp.example.test/', AUD = 'sentinelmesh';
async function setup() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const other = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  const verifier = new OidcVerifier({ issuer: ISS, audience: AUD, jwks: createLocalJWKSet({ keys: [jwk] }) });
  const mint = (claims: Record<string, unknown> = {}, o: { key?: any; iss?: string; aud?: string; exp?: string } = {}) =>
    new SignJWT({ sentinel_org: 'org_acme', sentinel_role: 'approver', email: 'a@acme.test', ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setSubject('u_oidc').setIssuer(o.iss ?? ISS).setAudience(o.aud ?? AUD).setIssuedAt().setExpirationTime(o.exp ?? '5m').sign(o.key ?? privateKey);
  return { verifier, mint, other };
}

describe('OIDC bearer auth', () => {
  it('accepts valid tokens and maps org/role claims', async () => {
    const { verifier, mint } = await setup();
    expect(await verifier.verify(await mint())).toEqual({ userId: 'u_oidc', orgId: 'org_acme', role: 'approver', email: 'a@acme.test' });
  });
  it.each([
    ['wrong issuer', (m: any) => m({}, { iss: 'https://evil.test/' })],
    ['wrong audience', (m: any) => m({}, { aud: 'other-app' })],
    ['expired', (m: any) => m({}, { exp: '-1m' })],
    ['signed by another key', (m: any, o: any) => m({}, { key: o.privateKey })],
    ['unknown role', (m: any) => m({ sentinel_role: 'root' })],
    ['no tenant', (m: any) => m({ sentinel_org: undefined })],
  ])('rejects %s', async (_n, f) => {
    const { verifier, mint, other } = await setup();
    expect(await verifier.verify(await f(mint, other))).toBeUndefined();
  });
  it('rejects unsigned (alg=none) and HMAC-forged tokens', async () => {
    const { verifier } = await setup();
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const none = `${b64({ alg: 'none' })}.${b64({ sub: 'x', iss: ISS, aud: AUD, exp: 9999999999, sentinel_org: 'org_acme', sentinel_role: 'admin' })}.`;
    expect(await verifier.verify(none)).toBeUndefined();
    const hs = await new SignJWT({ sentinel_org: 'org_acme', sentinel_role: 'admin' }).setProtectedHeader({ alg: 'HS256' }).setSubject('x').setIssuer(ISS).setAudience(AUD).setExpirationTime('5m').sign(new TextEncoder().encode('secret'));
    expect(await verifier.verify(hs)).toBeUndefined();
  });
  it('is enforced end-to-end by the guard; API keys can be disabled', async () => {
    const t = await boot(); const { verifier, mint } = await setup();
    const auth = t.app.get(AuthService); auth.oidc = verifier;
    const http = request(t.app.getHttpServer());
    await http.get('/api/v1/exposures/summary').set('Authorization', `Bearer ${await mint({ sentinel_role: 'viewer' })}`).expect(200);
    await http.get('/api/v1/exposures/summary').set('Authorization', 'Bearer garbage').expect(401);
    await http.post('/api/v1/approvals/x/decision').set('Authorization', `Bearer ${await mint({ sentinel_role: 'viewer' })}`).send({ decision: 'approved' }).expect(403);
    await http.get('/api/v1/exposures/summary').set('x-api-key', 'dev-viewer').expect(200);
    auth.allowApiKeys = false;
    await http.get('/api/v1/exposures/summary').set('x-api-key', 'dev-viewer').expect(401);
    await t.app.close();
  });
});
