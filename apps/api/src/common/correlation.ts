import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { Injectable, NestMiddleware } from '@nestjs/common';

/**
 * Correlation context. The mesh (Envoy) creates `x-request-id` and the trace spans, but it cannot copy headers from an inbound
 * request to the outbound calls a service makes: the application must. Only this allowlist is ever forwarded — never
 * credentials (authorization, x-api-key, cookies) — and only to mesh-internal destinations.
 */
export const PROPAGATE = ['x-request-id', 'x-tenant', 'traceparent', 'tracestate', 'baggage', 'b3'] as const;
export interface Correlation { requestId: string; tenant?: string; headers: Record<string, string> }

const als = new AsyncLocalStorage<Correlation>();
const ID = /^[A-Za-z0-9._:-]{8,128}$/;                 // also blocks log/header injection (no spaces, quotes, newlines, '%', ';')
const TENANT = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const TRACEPARENT = /^[\da-f]{2}-[\da-f]{32}-[\da-f]{16}-[\da-f]{2}$/;
const VALID: Record<string, (v: string) => boolean> = {
  'x-request-id': (v) => ID.test(v), 'x-tenant': (v) => TENANT.test(v), traceparent: (v) => TRACEPARENT.test(v),
  // bounded quantifiers only (no ambiguous nesting): linear time, the rule's heuristic is a false positive here
  // eslint-disable-next-line security/detect-unsafe-regex
  tracestate: (v) => v.length <= 512 && /^[\x20-\x7e]*$/.test(v), baggage: (v) => v.length <= 1024 && /^[\x20-\x7e]*$/.test(v), b3: (v) => /^[\da-f]{16,32}(-[\da-f]{16}(-[01d](-[\da-f]{16})?)?)?$|^[01d]$/.test(v),
};

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

export function fromHeaders(h: Record<string, string | string[] | undefined>): Correlation {
  const headers: Record<string, string> = {};
  for (const k of PROPAGATE) { const v = first(h[k]); if (typeof v === 'string' && VALID[k](v)) headers[k] = v; }
  headers['x-request-id'] ??= randomUUID();                // absent or malformed ⇒ mint a fresh one so every hop is traceable
  return { requestId: headers['x-request-id'], tenant: headers['x-tenant'], headers };
}

export const currentCorrelation = () => als.getStore();
export const runWithCorrelation = <T>(c: Correlation, fn: () => T): T => als.run(c, fn);
export const correlationFor = (requestId?: string, tenant?: string): Correlation => fromHeaders({ ...(requestId ? { 'x-request-id': requestId } : {}), ...(tenant ? { 'x-tenant': tenant } : {}) });

/** Headers to attach to a call to ANOTHER MESH SERVICE. Empty outside a request. */
export const propagationHeaders = (): Record<string, string> => ({ ...(als.getStore()?.headers ?? {}) });

@Injectable()
export class CorrelationMiddleware implements NestMiddleware {
  use(req: { headers: Record<string, string | string[] | undefined> }, res: { setHeader(k: string, v: string): void }, next: () => void) {
    const c = fromHeaders(req.headers);
    res.setHeader('x-request-id', c.requestId);            // the caller (and the browser/console) can quote it in a bug report
    als.run(c, next);
  }
}
