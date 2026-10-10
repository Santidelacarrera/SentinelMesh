import { HttpException, HttpStatus, Injectable, NestMiddleware } from '@nestjs/common';
import { createHash } from 'node:crypto';

/** Security headers for a JSON API (nothing here should ever be framed, sniffed or cached by shared caches). */
@Injectable()
export class SecurityHeaders implements NestMiddleware {
  use(req: any, res: any, next: () => void) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.removeHeader('X-Powered-By');
    next();
  }
}

/** Fixed-window limiter keyed by credential (hashed) or IP. Protects the engine and the audit trail from floods. */
@Injectable()
export class RateLimit implements NestMiddleware {
  private hits = new Map<string, { n: number; reset: number }>();
  private limit = Number(process.env.RATE_LIMIT_PER_MIN ?? 600);
  use(req: any, _res: any, next: () => void) {
    if (!this.limit) return next();
    const id = req.headers['x-api-key'] || req.headers['authorization'] || req.ip || 'anon';
    const key = createHash('sha256').update(String(id)).digest('hex').slice(0, 16);
    const t = Date.now(); let h = this.hits.get(key);
    if (!h || h.reset <= t) { h = { n: 0, reset: t + 60_000 }; this.hits.set(key, h); if (this.hits.size > 10_000) for (const [k, v] of this.hits) if (v.reset <= t) this.hits.delete(k); }
    if (++h.n > this.limit) { _res.setHeader('Retry-After', Math.ceil((h.reset - t) / 1000)); throw new HttpException('rate limit exceeded', HttpStatus.TOO_MANY_REQUESTS); }
    next();
  }
}
