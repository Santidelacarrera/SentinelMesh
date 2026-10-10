import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { Me } from './types';

export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }

export class Api {
  constructor(private key: string, private base = '/api/v1') {}
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    let r: Response;
    try { r = await fetch(this.base + path, { method, headers: { 'x-api-key': this.key, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); }
    catch { throw new ApiError(0, 'No se pudo contactar con la API. Comprueba que está en marcha.'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, explain(r.status, j as { message?: string | string[]; issues?: Array<{ path: string; message: string }> }));
    return j as T;
  }
  get = <T,>(p: string) => this.call<T>('GET', p);
  post = <T,>(p: string, b?: unknown) => this.call<T>('POST', p, b ?? {});
}

function explain(status: number, j: { message?: string | string[]; issues?: Array<{ path: string; message: string }> }): string {
  if (status === 401) return 'La clave de acceso no es válida.';
  if (status === 403) return typeof j.message === 'string' && j.message.includes('separation') ? 'No puedes aprobar un cambio que solicitaste tú. Pide a otra persona que lo firme.' : 'Tu rol no permite esta acción.';
  if (status === 409) return 'Esta decisión ya fue tomada por otra persona.';
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
  const [state, set] = useState<{ data?: T; error?: string; loading: boolean }>({ loading: !!path });
  const alive = useRef(true), seq = useRef(0);
  const load = useCallback(() => {
    if (!path) return;
    const my = ++seq.current;
    api.get<T>(path).then((data) => { if (alive.current && my === seq.current) set({ data, loading: false }); })
      .catch((e: Error) => { if (alive.current && my === seq.current) set((s) => ({ data: s.data, error: e.message, loading: false })); });
  }, [api, path]);
  useEffect(() => {
    alive.current = true; set((s) => ({ data: s.data, loading: !!path })); load();
    const t = pollMs ? setInterval(load, pollMs) : undefined; window.addEventListener('sm:refresh', load);
    return () => { alive.current = false; if (t) clearInterval(t); window.removeEventListener('sm:refresh', load); };
  }, [load, pollMs, path]);
  return { ...state, reload: load };
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
