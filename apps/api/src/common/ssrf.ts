import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

export class UnsafeUrlError extends Error {}

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}
const V4_BLOCKS: Array<[string, number]> = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

export function isPrivateIp(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) {
    const n = ipv4ToInt(ip);
    return V4_BLOCKS.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return (n & mask) === (ipv4ToInt(base) & mask);
    });
  }
  if (v === 6) {
    const l = ip.toLowerCase();
    if (l === '::1' || l === '::') return true;
    if (l.startsWith('::ffff:')) return isPrivateIp(l.slice(7));
    return /^(fc|fd|fe[89ab])/.test(l);
  }
  return true; // not an IP → treat as unsafe
}

export interface UrlPolicy {
  allowedHosts?: string[]; // exact-match allowlist (preferred)
  allowHttp?: boolean;
  resolve?: (host: string) => Promise<string[]>;
}

/** Validates an outbound URL (webhook target, healthcheck, analytics endpoint). */
export async function assertSafeUrl(raw: string, policy: UrlPolicy = {}): Promise<URL> {
  let u: URL;
  try { u = new URL(raw); } catch { throw new UnsafeUrlError('invalid URL'); }
  if (u.protocol !== 'https:' && !(policy.allowHttp && u.protocol === 'http:')) throw new UnsafeUrlError('scheme not allowed');
  if (u.username || u.password) throw new UnsafeUrlError('credentials in URL not allowed');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (policy.allowedHosts && !policy.allowedHosts.includes(host)) throw new UnsafeUrlError('host not in allowlist');
  const ips = isIP(host)
    ? [host]
    : await (policy.resolve ?? (async (h) => (await lookup(h, { all: true })).map((r) => r.address)))(host);
  if (ips.length === 0 || ips.some(isPrivateIp)) throw new UnsafeUrlError('host resolves to a private/reserved address');
  return u;
}
