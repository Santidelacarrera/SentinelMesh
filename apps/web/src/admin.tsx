import { useState } from 'react';
import { useResource, useSession, useToast, refreshAll } from './api';
import { Empty, ErrorBanner, Page, Skeleton, Tabs } from './ui/kit';
import { ago } from './lib/format';

type R = Record<string, any>;
const ROLES = ['viewer', 'analyst', 'approver', 'admin'];

/** Organisation administration: users, roles, plan and operational health. Only administrators see it; every action is audited by the API. */
export function Admin() {
  const [tab, setTab] = useState<'users' | 'roles' | 'plan' | 'health'>('users'), { api, me } = useSession(), toast = useToast(), [secret, setSecret] = useState('');
  const users = useResource<R[]>(me.role === 'admin' ? '/users' : null), roles = useResource<R[]>(me.role === 'admin' ? '/roles' : null), plan = useResource<R>('/plan'), health = useResource<R>(me.role === 'admin' ? '/ops/health' : null, 15000);
  const act = async (p: Promise<unknown>, ok: string) => { try { await p; toast(ok); refreshAll(); } catch (e) { toast((e as Error).message, 'err'); } };
  if (me.role !== 'admin') return <Page title="Administración"><Empty title="Solo administradores">Tu rol no permite gestionar usuarios, roles ni la salud operativa.</Empty></Page>;
  return (
    <Page title="Administración" lede="Usuarios, roles, plan y salud operativa de tu organización. Cada acción queda en la auditoría.">
      <Tabs tabs={[['users', 'Usuarios'], ['roles', 'Roles'], ['plan', 'Plan y uso'], ['health', 'Salud']]} value={tab} onChange={setTab} />
      <section className="panel" style={{ marginTop: 14 }}>
        {tab === 'users' && <>
          {users.error && <ErrorBanner message={users.error} retry={users.reload} />}
          {!users.data ? <Skeleton /> : <div className="tablewrap"><table><thead><tr><th>Usuario</th><th>Rol</th><th>MFA</th><th>Último acceso</th><th /></tr></thead><tbody>{users.data.map((u) => (
            <tr key={u.id}><td><b>{u.email}</b><div className="muted">{u.status}{u.locked ? ' · bloqueado' : ''}</div></td><td>{u.role}</td><td>{u.mfaEnabled ? 'sí' : 'no'}</td><td>{u.lastLoginAt ? ago(u.lastLoginAt) : 'nunca'}</td>
              <td><div className="row-actions" style={{ flexWrap: 'nowrap' }}>
                <button className="btn small" disabled={u.id === me.userId} onClick={() => void act(api.post(`/users/${u.id}/${u.status === 'active' ? 'disable' : 'enable'}`), u.status === 'active' ? 'Usuario deshabilitado' : 'Usuario habilitado')}>{u.status === 'active' ? 'Deshabilitar' : 'Habilitar'}</button>
                <button className="btn small" onClick={() => void act(api.post(`/users/${u.id}/revoke-sessions`), 'Sesiones revocadas')}>Revocar sesiones</button>
                <button className="btn small" onClick={async () => { try { const r = await api.post<{ token: string }>(`/users/${u.id}/reset-token`); setSecret(r.token); } catch (e) { toast((e as Error).message, 'err'); } }}>Token de restablecimiento</button></div></td></tr>))}</tbody></table></div>}
          {secret && <div className="note" style={{ margin: 16 }}><b>Token de un solo uso (30 min). Se muestra solo ahora; entrégalo por un canal seguro:</b><br /><code style={{ overflowWrap: 'anywhere' }}>{secret}</code> <button className="btn small" onClick={() => setSecret('')}>Ocultar</button></div>}
          <form className="formgrid" style={{ padding: 16 }} onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget); void act(api.post('/users', { email: String(f.get('email')), password: String(f.get('pw')), role: String(f.get('role')) }), 'Usuario creado'); e.currentTarget.reset(); }}>
            <label className="field"><span>Correo</span><input name="email" type="text" required /></label>
            <label className="field"><span>Contraseña inicial (≥12, 3 de 4 tipos)</span><input name="pw" type="password" autoComplete="new-password" required minLength={12} /></label>
            <label className="field"><span>Rol</span><select name="role" defaultValue="viewer">{ROLES.map((r) => <option key={r}>{r}</option>)}</select></label>
            <button className="btn primary">Crear usuario</button></form></>}
        {tab === 'roles' && (roles.error ? <ErrorBanner message={roles.error} retry={roles.reload} /> : !roles.data ? <Skeleton /> : roles.data.length === 0 ? <Empty title="Sin roles propios">Los roles base (viewer, analyst, approver, admin) siempre existen. Los roles propios son del plan Enterprise y se crean con POST /api/v1/roles.</Empty> : <ul className="list">{roles.data.map((r) => <li key={r.id}><div className="row" style={{ cursor: 'default' }}><span className="t">{r.name}</span><span className="m">{r.permissions.join(' · ')}</span></div></li>)}</ul>)}
        {tab === 'plan' && (!plan.data ? <Skeleton /> : <div className="body stack"><dl className="kv"><dt>Plan</dt><dd><b>{plan.data.plan}</b></dd><dt>Funciones</dt><dd>{plan.data.features.join(', ')}</dd>{Object.entries(plan.data.limits as R).map(([k, v]) => [<dt key={`k${k}`}>Límite: {k}</dt>, <dd key={`v${k}`}>{v === null ? 'sin límite' : String(v)}</dd>])}</dl><p className="muted">Las cifras de límite son marcadores ilustrativos del mecanismo de licenciamiento, no precios ni compromisos.</p></div>)}
        {tab === 'health' && (health.error ? <ErrorBanner message={health.error} retry={health.reload} /> : !health.data ? <Skeleton /> : <div className="body stack">
          <p><span className={`state ${health.data.status === 'ok' ? 'connected' : 'error'}`}>{health.data.status === 'ok' ? 'Todo en orden' : health.data.status === 'critical' ? 'Crítico' : 'Degradado'}</span> <span className="muted">cadena de auditoría {health.data.auditChain.ok ? 'íntegra' : `ROTA en ${health.data.auditChain.brokenAt}`} · cola: {health.data.queue.waiting} en espera, {health.data.queue.failed} fallidos</span></p>
          {health.data.issues.length === 0 ? <p className="muted">Sin incidencias operativas con los datos actuales.</p> : <ul className="list">{health.data.issues.map((i: R, n: number) => <li key={n}><div className="row" style={{ cursor: 'default' }}><span className="t">{i.area}</span><span className="m">{i.detail}</span></div></li>)}</ul>}</div>)}
      </section>
    </Page>
  );
}
