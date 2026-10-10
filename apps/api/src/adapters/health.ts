import { assertSafeUrl, UrlPolicy } from '../common/ssrf';
import { HealthChecker } from '../workflow/ports';

/**
 * Probes the dependent service WITH the candidate credential (Authorization: Bearer <secret>).
 * Target URLs come from operator config (service → URL), are re-validated against the SSRF policy on every call,
 * redirects are not followed (a redirect could bounce the secret to another host), and the secret never appears in the result.
 */
export class HttpHealthChecker implements HealthChecker {
  constructor(private o: { urls: Record<string, string>; getSecret: (credentialId: string, version: number) => Promise<string>; policy?: UrlPolicy; timeoutMs?: number; fetchImpl?: typeof fetch }) {}
  async check(service: string, credentialId: string, version: number) {
    const raw = this.o.urls[service]; if (!raw) return { healthy: false, detail: `no healthcheck URL configured for "${service}"` };
    try {
      const url = await assertSafeUrl(raw, this.o.policy);
      const secret = await this.o.getSecret(credentialId, version);
      const res = await (this.o.fetchImpl ?? fetch)(url, { headers: { authorization: `Bearer ${secret}` }, redirect: 'manual', signal: AbortSignal.timeout(this.o.timeoutMs ?? 5000) });
      return { healthy: res.status >= 200 && res.status < 300, detail: `HTTP ${res.status} from ${url.host}${url.pathname}` };
    } catch (e) { return { healthy: false, detail: `probe error: ${(e as Error).message.replace(/Bearer\s+\S+/g, 'Bearer [REDACTED]')}` }; }
  }
}
