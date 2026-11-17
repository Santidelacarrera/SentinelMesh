import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { Me } from './types';

export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }

/** Sends an API key (`x-api-key`) or, for tokens issued by /auth/login (`smt.…`), `Authorization: Bearer`. A 401 with a refresh token rotates the session once and retries. */
export class Api {
  constructor(private key: string, private base = '/api/v1', private refreshToken = '', private onTokens: (t: { accessToken: string; refreshToken: string }) => void = () => {}) {}
  private headers(): Record<string, string> { return { 'content-type': 'application/json', ...(this.key.startsWith('smt.') ? { authorization: `Bearer ${this.key}` } : { 'x-api-key': this.key }) }; }
  private async refresh(): Promise<boolean> {
    if (!this.refreshToken) return false;
    try {
      const r = await fetch(`${this.base}/auth/refresh`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ refreshToken: this.refreshToken }) });
      if (!r.ok) return false;
      const j = (await r.json()) as { accessToken: string; refreshToken: string }; this.key = j.accessToken; this.refreshToken = j.refreshToken; this.onTokens(j); return true;
    } catch { return false; }
  }
  async raw(method: string, path: string, body?: unknown, retry = true): Promise<Response> {
    let r: Response;
    try { r = await fetch(this.base + path, { method, headers: this.headers(), body: body === undefined ? undefined : JSON.stringify(body) }); }
    catch { throw new ApiError(0, 'No se pudo contactar con la API. Comprueba que está en marcha.'); }
    if (r.status === 401 && retry && (await this.refresh())) return this.raw(method, path, body, false);
    return r;
  }
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const r = await this.raw(method, path, body);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, explain(r.status, j as { message?: string | string[]; issues?: Array<{ path: string; message: string }> }));
    return j as T;
  }
  get = <T,>(p: string) => this.call<T>('GET', p);
  post = <T,>(p: string, b?: unknown) => this.call<T>('POST', p, b ?? {});
  /** Downloads a binary (e.g. a PDF) with this session's credentials and hands it to the browser. */
  async download(path: string, filename: string) {
    const r = await this.raw('GET', path);
    if (!r.ok) throw new ApiError(r.status, explain(r.status, (await r.json().catch(() => ({}))) as { message?: string }));
    const url = URL.createObjectURL(await r.blob()), a = document.createElement('a'); a.href = url; a.download = filename; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
}

function explain(status: number, j: { message?: string | string[]; issues?: Array<{ path: string; message: string }> }): string {
  if (status === 401) return 'Las credenciales no son válidas o la sesión caducó.';
  if (status === 402) return `Esta función no está incluida en el plan actual${typeof j.message === 'string' ? ` (${j.message})` : ''}.`;
  if (status === 403) return typeof j.message === 'string' && j.message.includes('separation') ? 'No puedes aprobar un cambio que solicitaste tú. Pide a otra persona que lo firme.' : 'Tu rol no permite esta acción.';
  if (status === 409) return typeof j.message === 'string' && !j.message.startsWith('already') ? j.message : 'Esta decisión ya fue tomada por otra persona.';
  if (status === 429) return 'Demasiadas peticiones. Espera unos segundos.';
  if (j.issues?.length) return j.issues.map((i) => `${i.path || 'dato'}: ${i.message}`).join(' · ');
  return (Array.isArray(j.message) ? j.message.join(', ') : j.message) ?? `Error ${status}`;
}

export interface Session { api: Api; me: Me; signOut: () => void; refreshCounts: () => void }
/** Any mutation calls this so every mounted view reloads (counts, lists). */
export const refreshAll = () => window.dispatchEvent(new Event('sm:refresh'));
export const SessionCtx = createContext<Session>(null as never);
export const useSession = () => useContext(SessionCtx);

export interface Resource<T> { data?: T; error?: string; loading: boolean; reload: () => void }
/** GET with optional polling. Keeps stale data on screen while reloading and never updates after unmount. */
export function useResource<T>(path: string | null, pollMs = 0): Resource<T> {
  const { api } = useSession();
  // `for` records which path the data belongs to, so `loading` is derived (no synchronous setState inside the effect).
  const [state, set] = useState<{ data?: T; error?: string; for?: string | null }>({});
  const alive = useRef(true), seq = useRef(0);
  const load = useCallback(() => {
    if (!path) return;
    const my = ++seq.current;
    api.get<T>(path).then((data) => { if (alive.current && my === seq.current) set({ data, for: path }); })
      .catch((e: Error) => { if (alive.current && my === seq.current) set((s) => ({ data: s.data, error: e.message, for: path })); });
  }, [api, path]);
  useEffect(() => {
    alive.current = true; load();
    const t = pollMs ? setInterval(load, pollMs) : undefined; window.addEventListener('sm:refresh', load);
    return () => { alive.current = false; if (t) clearInterval(t); window.removeEventListener('sm:refresh', load); };
  }, [load, pollMs, path]);
  return { data: state.data, error: state.error, loading: !!path && state.for !== path, reload: load };
}

// ── toasts ──
export interface Toast { id: number; text: string; kind: 'ok' | 'err' }
export const ToastCtx = createContext<(text: string, kind?: 'ok' | 'err') => void>(() => {});
export const useToast = () => useContext(ToastCtx);

// ── tiny hash router ──
export interface Route { name: string; id?: string; query: URLSearchParams }
export function parseHash(h: string): Route {
  const [path, q = ''] = h.replace(/^#\/?/, '').split('?');
  const [name = 'resumen', id] = path.split('/').filter(Boolean);
  return { name: name || 'resumen', id: id && decodeURIComponent(id), query: new URLSearchParams(q) };
}
export function useRoute(): Route {
  const [r, set] = useState(() => parseHash(location.hash));
  useEffect(() => { const f = () => set(parseHash(location.hash)); addEventListener('hashchange', f); return () => removeEventListener('hashchange', f); }, []);
  return r;
}
export const go = (path: string) => { location.hash = path; };
