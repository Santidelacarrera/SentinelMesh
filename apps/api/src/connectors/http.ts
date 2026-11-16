import { assertSafeUrl, UrlPolicy } from '../common/ssrf';
import { redactString } from '../common/mask';
import { propagationHeaders } from '../common/correlation';

/**
 * Shared transport for every connector: SSRF-checked URLs, per-connector rate limit (token bucket), bounded retries with
 * exponential backoff + jitter (honouring Retry-After), request timeout, secret-free error messages, and OAuth2 token
 * renewal (single-flight; a 401 invalidates the cached token and retries once with a fresh one).
 */
export class ConnectorError extends Error {
  constructor(message: string, public status = 0, public retriable = false) { super(message); }
}

export class TokenBucket {
  private tokens: number; private last: number;
  constructor(private ratePerSec: number, private burst = Math.max(1, Math.ceil(ratePerSec)), private now = () => Date.now()) { this.tokens = burst; this.last = now(); }
  /** ms to wait before one request may go out (0 = go now). */
  take(): number {
    const t = this.now(); this.tokens = Math.min(this.burst, this.tokens + ((t - this.last) / 1000) * this.ratePerSec); this.last = t;
    if (this.tokens >= 1) { this.tokens -= 1; return 0; }
    const wait = Math.ceil(((1 - this.tokens) / this.ratePerSec) * 1000); this.tokens -= 1; return wait;
  }
}

export interface HttpOptions {
  baseUrl: string; fetch?: typeof fetch; rps?: number; retries?: number; timeoutMs?: number; sleep?: (ms: number) => Promise<void>; secrets?: string[]; policy?: UrlPolicy;
}
export interface ReqOptions { headers?: Record<string, string>; query?: Record<string, string | number | undefined>; json?: unknown; form?: Record<string, string>; noAuth?: boolean; absolute?: boolean }
export interface HttpResult<T = any> { status: number; headers: Headers; body: T }

export function connectorUrlPolicy(): UrlPolicy {
  const priv = (() => { try { return JSON.parse(process.env.CONNECTOR_PRIVATE_HOSTS ?? '[]') as string[]; } catch { return []; } })();
  return { allowHttp: process.env.CONNECTOR_ALLOW_HTTP === '1', allowPrivateHosts: priv };
}

export class HttpClient {
  private bucket: TokenBucket; private f: typeof fetch; private sleep: (ms: number) => Promise<void>; calls = 0;
  tokenProvider?: { get(): Promise<string>; invalidate(): void };
  /** For APIs with several audiences (e.g. Microsoft Graph + Defender): picks the token source per URL. */
  tokenSelector?: (url: URL) => { get(): Promise<string>; invalidate(): void } | undefined;
  constructor(private o: HttpOptions) {
    this.bucket = new TokenBucket(o.rps ?? 5); this.f = o.fetch ?? fetch; this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }
  private clean(s: string) { let out = redactString(s); for (const x of this.o.secrets ?? []) if (x && x.length >= 6) out = out.split(x).join('[REDACTED]'); return out.slice(0, 400); }

  async request<T = any>(method: string, path: string, r: ReqOptions = {}): Promise<HttpResult<T>> {
    const url = r.absolute ? new URL(path) : new URL(path.replace(/^\//, ''), this.o.baseUrl.replace(/\/?$/, '/'));
    for (const [k, v] of Object.entries(r.query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
    await assertSafeUrl(url.toString(), this.o.policy ?? connectorUrlPolicy());                  // every hop (incl. pagination links) passes the SSRF policy
    const attempts = (this.o.retries ?? 3) + 1; let renewed = false, lastErr: ConnectorError | undefined;
    for (let n = 1; n <= attempts; n++) {
      const wait = this.bucket.take(); if (wait) await this.sleep(wait);
      try {
        const headers: Record<string, string> = { accept: 'application/json', ...propagationHeaders(), ...r.headers };
        let body: string | undefined;
        if (r.json !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(r.json); }
        if (r.form) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(r.form).toString(); }
        const tp = r.noAuth ? undefined : (this.tokenSelector?.(url) ?? this.tokenProvider);
        if (tp) headers['authorization'] = `Bearer ${await tp.get()}`;
        this.calls++;
        const res = await this.f(url, { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(this.o.timeoutMs ?? 15000) });
        if (res.status === 401 && tp && !renewed) { renewed = true; tp.invalidate(); n--; continue; }
        if (res.status === 429 || res.status >= 500) {
          const ra = Number(res.headers.get('retry-after')); const delay = Number.isFinite(ra) && ra > 0 ? Math.min(ra, 30) * 1000 : Math.min(30000, 250 * 2 ** (n - 1)) + Math.floor(Math.random() * 100);
          lastErr = new ConnectorError(`HTTP ${res.status} from ${url.host}`, res.status, true);
          if (n < attempts) { await this.sleep(delay); continue; }
          throw lastErr;
        }
        const text = await res.text(); let parsed: unknown = text;
        try { parsed = text ? JSON.parse(text) : undefined; } catch { /* non-JSON body kept as text */ }
        if (res.status >= 300) throw new ConnectorError(`HTTP ${res.status} from ${url.host}: ${this.clean(typeof parsed === 'string' ? parsed : JSON.stringify(parsed ?? ''))}`, res.status, false);
        return { status: res.status, headers: res.headers, body: parsed as T };
      } catch (e) {
        if (e instanceof ConnectorError) throw e;
        lastErr = new ConnectorError(`network error calling ${url.host}: ${this.clean((e as Error).message)}`, 0, true);
        if (n < attempts) { await this.sleep(Math.min(30000, 250 * 2 ** (n - 1))); continue; }
        throw lastErr;
      }
    }
    throw lastErr ?? new ConnectorError('request failed');
  }
  get<T = any>(path: string, r?: ReqOptions) { return this.request<T>('GET', path, r); }
  post<T = any>(path: string, r?: ReqOptions) { return this.request<T>('POST', path, r); }
}

/** OAuth2 client-credentials / JWT-bearer token cache with early renewal and a single in-flight refresh. */
export class TokenManager {
  private tok?: { v: string; exp: number }; private inflight?: Promise<string>;
  constructor(private fetchToken: () => Promise<{ token: string; expiresInSec: number }>, private skewSec = 60, private now = () => Date.now()) {}
  async get(): Promise<string> {
    if (this.tok && this.tok.exp - this.skewSec * 1000 > this.now()) return this.tok.v;
    this.inflight ??= this.fetchToken().then((r) => { this.tok = { v: r.token, exp: this.now() + r.expiresInSec * 1000 }; return r.token; }).finally(() => { this.inflight = undefined; });
    return this.inflight;
  }
  invalidate() { this.tok = undefined; }
  /** When the current token expires (for display); undefined before the first fetch. */
  get expiresAt() { return this.tok && new Date(this.tok.exp).toISOString(); }
}
