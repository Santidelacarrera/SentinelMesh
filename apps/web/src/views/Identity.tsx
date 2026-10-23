import { useRef, useState } from 'react';
import { useResource, useSession, useToast, refreshAll } from '../api';
import { Empty, ErrorBanner, Page, Skeleton } from '../ui/kit';
import { ago } from '../lib/format';
import { DiffView } from './Decisions';
import type { IdentityAudit, Plan } from '../types';

const lines = (s: string) => s.split(/\n+/).map((x) => x.trim()).filter(Boolean);

export function Identity() {
  const { api, me } = useSession(), toast = useToast(), past = useResource<IdentityAudit[]>('/iam/audits');
  const [busy, setBusy] = useState(false), [err, setErr] = useState(''), [res, setRes] = useState<{ audit: IdentityAudit; plan?: Plan }>();
  const form = useRef<HTMLFormElement>(null);
  const run = async (send: boolean) => {
    if (!form.current?.reportValidity()) return; const d = new FormData(form.current); setBusy(true); setErr('');
    try {
      const events = lines(String(d.get('events'))).flatMap((l) => { const m = /^(.+?)\s*[x×]\s*(\d+)$/.exec(l); return m ? Array(Math.min(Number(m[2]), 5000)).fill(m[1]) : [l]; });
      const r = await api.post<{ audit: IdentityAudit; plan?: Plan }>('/iam/audit-roles', { roleName: String(d.get('role')), critical: d.get('critical') === 'on', grantedActions: lines(String(d.get('granted'))), auditEvents: events, resources: lines(String(d.get('resources')) || '*'), ...(String(d.get('replace')) ? { replacePolicyName: String(d.get('replace')) } : {}), submitForApproval: send });
      setRes(r); past.reload(); if (send) refreshAll(); toast(send && r.plan ? 'Recorte enviado a Decisiones.' : 'Análisis listo. No se ha cambiado ningún permiso.');
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  const a = res?.audit;
  return (
    <Page title="Identidades" lede="Compara lo que un rol puede hacer con lo que hizo en los logs de auditoría y propone una política de mínimo privilegio.">
      <div className="split identity">
        <form ref={form} className="panel" onSubmit={(e) => { e.preventDefault(); void run(false); }} aria-label="Analizar un rol">
          <header><h2>Analizar un rol</h2></header>
          <div className="body stack" style={{ gap: 12 }}>
            <label className="field"><span>Nombre del rol</span><input type="text" name="role" required defaultValue="billing-batch-role" /></label>
            <label className="field"><span>Permisos concedidos (uno por línea)</span><textarea name="granted" required rows={5} defaultValue={'s3:GetObject\ns3:PutObject\ns3:DeleteObject\niam:PassRole\nsqs:*'} /></label>
            <label className="field"><span>Eventos vistos en los logs (uno por línea; «s3:GetObject × 240» repite)</span><textarea name="events" rows={4} defaultValue={'s3:GetObject × 240\ns3:PutObject × 31'} /></label>
            <label className="field"><span>Recursos</span><input type="text" name="resources" defaultValue="*" /></label>
            <label className="field"><span>Política inline actual a sustituir (opcional)</span><input type="text" name="replace" placeholder="p. ej. broad-access" pattern="[\w+=,.@\-]*" /></label>
            <label style={{ display: 'flex', gap: 8 }}><input type="checkbox" name="critical" /> Es un rol crítico</label>
            {err && <p role="alert" style={{ color: 'var(--risk)' }}>{err}</p>}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}><button className="btn primary" disabled={busy}>Analizar</button>
              <button type="button" className="btn" disabled={busy || me.role === 'viewer'} onClick={() => void run(true)}>Analizar y proponer el recorte</button></div>
          </div>
        </form>
        <div className="stack">
          {a ? (
            <section className="panel"><header><h2>{a.roleName}</h2><span className="chip">{Math.round(a.usageRatio * 100)}% de los permisos en uso</span></header>
              <div className="body stack">
                <div className="usage" role="img" aria-label={`${a.used.length} de ${a.granted.length} permisos usados`}><i style={{ width: `${a.usageRatio * 100}%` }} /></div>
                <div className="perms">{a.granted.map((g) => <span key={g} className={`perm ${a.unused.includes(g) ? 'unused' : 'used'}`}>{g}</span>)}</div>
                <p className="muted">Verde: se usó. Tachado en rojo: no aparece en el periodo auditado y se propone quitar.</p>
                {res?.plan ? <><DiffView diff={res.plan.diff} /><a className="btn sign" style={{ textDecoration: 'none', justifySelf: 'start' }} href="#/decisiones">Ir a Decisiones</a></>
                  : <pre className="diff" style={{ padding: 12, margin: 0 }}>{JSON.stringify(a.proposedPolicy, null, 2)}</pre>}
              </div></section>
          ) : <section className="panel"><Empty title="Sin análisis todavía">Rellena el formulario. El análisis nunca modifica permisos: solo propone.</Empty></section>}
          <section className="panel"><header><h3>Análisis anteriores</h3></header>
            {past.error ? <ErrorBanner message={past.error} retry={past.reload} /> : !past.data ? <Skeleton rows={2} /> : past.data.length === 0 ? <Empty title="Todavía ninguno" /> : (
              <ul className="list">{past.data.map((p) => <li key={p.id}><div className="row" style={{ cursor: 'default' }}><span className="t">{p.roleName}{p.critical && <span className="chip risk" style={{ marginLeft: 8 }}>crítico</span>}</span><span className="m"><span>{p.unused.length} permisos sin usar de {p.granted.length}</span><span>{ago(p.createdAt)}</span></span></div></li>)}</ul>)}</section>
        </div>
      </div>
    </Page>
  );
}
