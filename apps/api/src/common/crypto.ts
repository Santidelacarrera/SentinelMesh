import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (pw: string | Buffer, salt: Buffer, len: number, o: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;
const P = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// ───────── passwords ─────────
export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16), h = await scrypt(pw, salt, 32, P);
  return `scrypt$${P.N}$${P.r}$${P.p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, n, r, p, s, h] = stored.split('$');
  if (alg !== 'scrypt' || !s || !h) return false;
  const want = Buffer.from(h, 'base64');
  const got = await scrypt(pw, Buffer.from(s, 'base64'), want.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: P.maxmem });
  return got.length === want.length && timingSafeEqual(got, want);
}
/** Used to burn the same time when the account does not exist (no user enumeration by timing). */
export const DUMMY_HASH = `scrypt$${P.N}$${P.r}$${P.p}$${Buffer.alloc(16, 1).toString('base64')}$${Buffer.alloc(32, 2).toString('base64')}`;

const COMMON = new Set(['password1234', 'passw0rd1234', 'qwerty123456', '123456789012', 'administrator', 'letmein12345', 'welcome12345']);
/** Password policy (NIST 800-63B flavoured: length first, no composition theatre, deny-list, no identifier reuse). Returns the problems found. */
export function passwordProblems(pw: string, email = ''): string[] {
  const p: string[] = [];
  if (pw.length < 12) p.push('must be at least 12 characters');
  if (pw.length > 256) p.push('must be at most 256 characters');
  if (new Set(pw).size < 6) p.push('is too repetitive');
  if (COMMON.has(pw.toLowerCase())) p.push('is a commonly used password');
  const local = email.split('@')[0]?.toLowerCase();
  if (local && local.length >= 4 && pw.toLowerCase().includes(local)) p.push('must not contain your email name');
  if ([/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length < 3) p.push('must mix at least 3 of: lowercase, uppercase, digits, symbols');
  return p;
}

// ───────── tokens ─────────
export const sha256hex = (s: string) => createHash('sha256').update(s).digest('hex');
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');
export const safeEqualHex = (a: string, b: string) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };

// ───────── secrets at rest (AES-256-GCM, key rotation) ─────────
export class SecretBox {
  private keys = new Map<string, Buffer>(); private current: string;
  constructor(current: Buffer, previous: Buffer[] = []) {
    this.current = SecretBox.kid(current); this.keys.set(this.current, current);
    for (const k of previous) this.keys.set(SecretBox.kid(k), k);
  }
  private static kid(k: Buffer) { return createHash('sha256').update(k).digest('hex').slice(0, 8); }
  static fromEnv(env = process.env): SecretBox {
    const parse = (v: string) => { const b = Buffer.from(v, 'base64'); if (b.length !== 32) throw new Error('SECRETS_ENCRYPTION_KEY must be 32 bytes, base64-encoded'); return b; };
    if (env.SECRETS_ENCRYPTION_KEY) return new SecretBox(parse(env.SECRETS_ENCRYPTION_KEY), (env.SECRETS_ENCRYPTION_KEY_PREVIOUS ?? '').split(',').filter(Boolean).map(parse));
    if (env.NODE_ENV === 'production') throw new Error('production requires SECRETS_ENCRYPTION_KEY (base64, 32 bytes)');
    return new SecretBox(randomBytes(32));            // dev/test: ephemeral key, nothing encrypted survives a restart
  }
  encrypt(plain: string, aad = ''): string {
    const iv = randomBytes(12), k = this.keys.get(this.current)!, c = createCipheriv('aes-256-gcm', k, iv);
    c.setAAD(Buffer.from(aad)); const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return ['v1', this.current, iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
  }
  decrypt(blob: string, aad = ''): string {
    const [v, kid, iv, tag, ct] = blob.split(':');
    const k = this.keys.get(kid);
    if (v !== 'v1' || !k || !iv || !tag || !ct) throw new Error('cannot decrypt: unknown format or key');
    const d = createDecipheriv('aes-256-gcm', k, Buffer.from(iv, 'base64')); d.setAAD(Buffer.from(aad)); d.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
  }
  /** True when the blob was sealed with an older key and should be re-encrypted. */
  needsRotation(blob: string) { return blob.split(':')[1] !== this.current; }
}

// ───────── TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ─────────
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(buf: Buffer): string { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; }
export function unbase32(s: string): Buffer { let bits = ''; for (const c of s.replace(/=+$/, '').toUpperCase()) { const i = B32.indexOf(c); if (i < 0) throw new Error('invalid base32'); bits += i.toString(2).padStart(5, '0'); } const out: number[] = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); }
export const newTotpSecret = () => base32(randomBytes(20));
export function totpAt(secret: string, step: number, digits = 6): string {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac('sha1', unbase32(secret)).update(msg).digest(), o = h[h.length - 1] & 0xf;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}
/** Returns the matching time step (for replay protection) or undefined. Accepts ±1 step of clock drift. */
export function verifyTotp(secret: string, code: string, nowMs = Date.now()): number | undefined {
  if (!/^\d{6}$/.test(code)) return undefined;
  const step = Math.floor(nowMs / 30000);
  for (const s of [step, step - 1, step + 1]) { const c = totpAt(secret, s); if (timingSafeEqual(Buffer.from(c), Buffer.from(code))) return s; }
  return undefined;
}
export const totpUri = (secret: string, account: string, issuer = 'SentinelMesh') => `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
