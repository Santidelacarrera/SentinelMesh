import { LoggerService } from '@nestjs/common';
import { currentCorrelation } from './correlation';
import { redactString } from './mask';

/** One JSON object per line (LOG_FORMAT=json, default in production): machine-parseable, correlated by request id, secrets redacted. */
export class JsonLogger implements LoggerService {
  constructor(private out: (line: string) => void = (l) => process.stdout.write(`${l}\n`)) {}
  private emit(level: string, message: unknown, context?: string, extra?: Record<string, unknown>) {
    const c = currentCorrelation();
    this.out(JSON.stringify({ ts: new Date().toISOString(), level, context, msg: redactString(typeof message === 'string' ? message : JSON.stringify(message)), requestId: c?.requestId, tenant: c?.tenant, ...extra }));
  }
  log(m: unknown, ctx?: string) { this.emit('info', m, ctx); }
  error(m: unknown, trace?: string, ctx?: string) { this.emit('error', m, ctx, trace ? { stack: redactString(String(trace)).slice(0, 2000) } : undefined); }
  warn(m: unknown, ctx?: string) { this.emit('warn', m, ctx); }
  debug(m: unknown, ctx?: string) { this.emit('debug', m, ctx); }
  verbose(m: unknown, ctx?: string) { this.emit('verbose', m, ctx); }
}
export const useJsonLogs = () => (process.env.LOG_FORMAT ?? (process.env.NODE_ENV === 'production' ? 'json' : 'text')) === 'json';
