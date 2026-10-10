/** Secret masking. Everything that reaches logs / audit trail goes through here. */
const PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[REDACTED:PRIVATE_KEY]'],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED:AWS_KEY_ID]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED:GITHUB_TOKEN]'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED:SLACK_TOKEN]'],
  [/\bsk_(live|test)_[A-Za-z0-9]{16,}\b/g, '[REDACTED:STRIPE_KEY]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[REDACTED:JWT]'],
  [/(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, '$1[REDACTED]'],
  [
    /((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization)["']?\s*[:=]\s*["']?)([^\s"',;}]{4,})/gi,
    '$1[REDACTED]',
  ],
];

export function redactString(input: string): string {
  return PATTERNS.reduce((acc, [re, rep]) => acc.replace(re, rep), input);
}

/** Deep-redacts any JSON-like value. Never mutates the input. */
export function redact<T>(value: T): T {
  return walk(value, 0) as T;
}

const SENSITIVE_KEY = /pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|authorization|signature/i;

function walk(v: unknown, depth: number): unknown {
  if (depth > 12) return '[TRUNCATED]';
  if (typeof v === 'string') return redactString(v);
  if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) {
      out[k] = SENSITIVE_KEY.test(k) && typeof val === 'string' ? '[REDACTED]' : walk(val, depth + 1);
    }
    return out;
  }
  return v;
}

/** Keeps just enough of a secret to identify it (e.g. `AKIA****MPLE`) — never the full value. */
export function maskSecret(secret: string): string {
  if (secret.length <= 8) return '*'.repeat(secret.length);
  return `${secret.slice(0, 4)}${'*'.repeat(4)}${secret.slice(-2)}`;
}
