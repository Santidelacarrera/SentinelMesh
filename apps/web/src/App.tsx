import { ReactNode, useCallback, useEffect, useMemo, useState } from 'react';
import { Api, SessionCtx, ToastCtx, Toast, useRoute, useResource, useSession, refreshAll } from './api';
import type { Approval, Me } from './types';
import { Overview } from './views/Overview';
import { Findings } from './views/Findings';
import { Decisions } from './views/Decisions';
import { Executions } from './views/Executions';
import { Incidents } from './views/Incidents';
import { Identity } from './views/Identity';
import { Credentials } from './views/Credentials';
import { Audit } from './views/Audit';
import { Cases, Ctem, Executive, Iam, Integrations, Reports, Soar } from './ent';

const Logo = ({ size = 28 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
    <g stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round"><path d="M16 4l10.4 6v12L16 28 5.6 22V10z" opacity=".55" /><path d="M16 4v24M5.6 10L26.4 22M26.4 10L5.6 22" opacity=".3" /></g>
    <circle cx="16" cy="16" r="4.2" fill="#8e89ff" /><circle cx="16" cy="4" r="2" fill="currentColor" /><circle cx="26.4" cy="10" r="2" fill="currentColor" /><circle cx="26.4" cy="22" r="2" fill="currentColor" /><circle cx="16" cy="28" r="2" fill="currentColor" /><circle cx="5.6" cy="22" r="2" fill="currentColor" /><circle cx="5.6" cy="10" r="2" fill="currentColor" />
  </svg>
);

const NAV: Array<[string, string]> = [['ejecutivo', 'Ejecutiva'], ['ctem', 'CTEM'], ['iam', 'IAM'], ['soar', 'SOAR'], ['casos', 'Casos'], ['integraciones', 'Integraciones'], ['informes', 'Informes'], ['resumen', 'Resumen'], ['hallazgos', 'Hallazgos'], ['decisiones', 'Decisiones'], ['ejecuciones', 'Ejecuciones'], ['incidentes', 'Incidentes'], ['identidades', 'Identidades'], ['credenciales', 'Credenciales'], ['auditoria', 'Auditoría']];

function Login({ onKey, error }: { onKey: (k: string, refresh?: string) => void; error?: string }) {
  const [msg, setMsg] = useState('');
  const userLogin = async (f: FormData) => {
    setMsg('');
    const r = await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ org: String(f.get('org')), email: String(f.get('email')), password: String(f.get('pw')), ...(f.get('totp') ? { totp: String(f.get('totp')) } : {}) }) }).catch(() => undefined);
    if (!r?.ok) return setMsg('Credenciales no válidas, cuenta bloqueada o MFA incorrecto.');
    const j = (await r.json()) as { accessToken: string; refreshToken: string }; onKey(j.accessToken, j.refreshToken);
  };
  return <div className="login"><form onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget); if (f.get('email')) void userLogin(f); else onKey(String(f.get('k')).trim()); }}>
    <h1><Logo size={36} /> SentinelMesh</h1><p className="muted">Consola de exposición, identidades y respuesta. Cada cambio destructivo requiere una firma humana.</p>
    <label className="field"><span>Clave de acceso (API)</span><input name="k" type="password" autoComplete="off" /></label>
    <details><summary className="muted">o entra con usuario</summary><div className="stack" style={{ gap: 10, marginTop: 10 }}><label className="field"><span>Organización</span><input name="org" type="text" autoComplete="organization" /></label><label className="field"><span>Correo</span><input name="email" type="text" autoComplete="username" /></label><label className="field"><span>Contraseña</span><input name="pw" type="password" autoComplete="current-password" /></label><label className="field"><span>Código MFA (si lo tienes)</span><input name="totp" type="text" inputMode="numeric" /></label></div></details>
    {msg && <p role="alert" style={{ color: 'var(--risk)' }}>{msg}</p>}
    {error && <p role="alert" style={{ color: 'var(--risk)' }}>{error}</p>}
    <button className="btn primary">Entrar</button>
    {import.meta.env.DEV && <p className="muted">Entorno de desarrollo: prueba dev-viewer, dev-analyst o dev-approver.</p>}</form></div>;
}

export function App() {
  const [key, setKey] = useState(() => { try { return sessionStorage.getItem('sm_key') ?? ''; } catch { return ''; } });
  const [who, setWho] = useState<{ key: string; me: Me }>(), [error, setError] = useState<string>();
  const me = who?.key === key ? who.me : undefined;      // a stale identity from a previous key is never shown
  const [refresh, setRefresh] = useState(() => { try { return sessionStorage.getItem('sm_refresh') ?? ''; } catch { return ''; } });
  const api = useMemo(() => new Api(key, '/api/v1', refresh, (t) => { try { sessionStorage.setItem('sm_key', t.accessToken); sessionStorage.setItem('sm_refresh', t.refreshToken); } catch { /* private mode */ } setRefresh(t.refreshToken); }), [key, refresh]);
  useEffect(() => { if (!key) return; api.get<Me>('/me').then((m) => setWho({ key, me: m })).catch((e: Error) => { setError(e.message); setKey(''); try { sessionStorage.removeItem('sm_key'); } catch { /* private mode */ } }); }, [api, key]);
  const signIn = (k: string, r = '') => { setError(undefined); try { sessionStorage.setItem('sm_key', k); sessionStorage.setItem('sm_refresh', r); } catch { /* private mode */ } setRefresh(r); setKey(k); };
  const signOut = () => { try { sessionStorage.removeItem('sm_key'); } catch { /* ignore */ } setKey(''); };
  if (!key) return <Login onKey={signIn} error={error} />;
  if (!me) return <div className="login"><div className="skel" style={{ width: 220 }} aria-busy="true" aria-label="Entrando" /></div>;
  return <Shell api={api} me={me} signOut={signOut} />;
}

function Shell({ api, me, signOut }: { api: Api; me: Me; signOut: () => void }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toast = useCallback((text: string, kind: 'ok' | 'err' = 'ok') => { const id = Date.now() + Math.random(); setToasts((t) => [...t, { id, text, kind }]); setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000); }, []);
  const route = useRoute();
  const session = useMemo(() => ({ api, me, signOut, refreshCounts: refreshAll }), [api, me, signOut]);
  return (
    <SessionCtx.Provider value={session}><ToastCtx.Provider value={toast}><Frame route={route} />
      <div className="toast-host" role="status" aria-live="polite">{toasts.map((t) => <div key={t.id} className={`toast ${t.kind === 'err' ? 'err' : ''}`}>{t.text}</div>)}</div></ToastCtx.Provider></SessionCtx.Provider>
  );
}

function Frame({ route }: { route: ReturnType<typeof useRoute> }) {
  const pend = useResource<Approval[]>('/approvals?status=pending', 5000), count = pend.data?.length ?? 0;
  const { me, signOut } = useSession();
  useEffect(() => { document.title = `${count ? `(${count}) ` : ''}SentinelMesh`; }, [count]);
  let view: ReactNode;
  switch (route.name) {
    case 'ejecutivo': view = <Executive />; break;
    case 'ctem': view = <Ctem />; break;
    case 'iam': view = <Iam />; break;
    case 'soar': view = <Soar />; break;
    case 'casos': view = <Cases id={route.id} />; break;
    case 'integraciones': view = <Integrations />; break;
    case 'informes': view = <Reports />; break;
    case 'hallazgos': view = <Findings id={route.id} query={route.query} />; break;
    case 'decisiones': view = <Decisions id={route.id} />; break;
    case 'ejecuciones': view = <Executions id={route.id} />; break;
    case 'incidentes': view = <Incidents id={route.id} />; break;
    case 'identidades': view = <Identity />; break;
    case 'credenciales': view = <Credentials />; break;
    case 'auditoria': view = <Audit />; break;
    default: view = <Overview />;
  }
  const active = NAV.some(([k]) => k === route.name) ? route.name : 'resumen';
  return (
    <div className="shell">
      <aside className="rail"><div className="brand"><Logo /> SentinelMesh</div>
        <nav className="nav" aria-label="Principal">{NAV.map(([k, l]) => <a key={k} href={`#/${k}`} aria-current={active === k ? 'page' : undefined}>{l}{k === 'decisiones' && count > 0 && <span className="count" aria-label={`${count} pendientes`}>{count}</span>}</a>)}</nav>
        <div className="rail-foot"><div><div className="who">{me.email || me.userId}</div><div className="role">Rol {me.role}</div></div><button onClick={signOut}>Salir</button></div></aside>
      <main className="main" id="main" key={route.name}>{view}</main>
    </div>
  );
}
