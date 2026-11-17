import { ReactNode, useState } from 'react';
import { useResource, useSession, useToast, refreshAll } from './api';
import { Empty, ErrorBanner, Page, Sev, Skeleton, Tabs } from './ui/kit';
import { SEV_LABEL, ago, clock } from './lib/format';
import { HoldToSign } from './ui/kit';
import type { Severity } from './types';

/* Loosely typed on purpose: these views only display what the API returns. */
type R = Record<string, any>;
interface Paged { total: number; items: R[] }
const LIMIT = 25;

export const STATE_LABEL: Record<string, string> = { not_configured: 'No configurada', configured: 'Configurada', connected: 'Conectada', syncing: 'Sincronizando', error: 'Con errores', disabled: 'Deshabilitada' };
export const VERIF_LABEL: Record<string, string> = { simulated: 'Simulada (endpoint local de pruebas)', implemented: 'Implementada, sin verificar contra un servicio real', connected: 'Conexión real comprobada', not_implemented: 'No implementada' };
const sev = (s: string) => (s in SEV_LABEL ? <Sev level={s as Severity} /> : <span className="chip">{s}</span>);

function Pager({ total, offset, set }: { total: number; offset: number; set: (n: number) => void }) {
  if (total <= LIMIT) return null;
  return <div className="pager"><span>{offset + 1}–{Math.min(total, offset + LIMIT)} de {total}</span><button className="btn small" disabled={offset === 0} onClick={() => set(Math.max(0, offset - LIMIT))}>Anterior</button><button className="btn small" disabled={offset + LIMIT >= total} onClick={() => set(offset + LIMIT)}>Siguiente</button></div>;
}
const Kpi = ({ n, l, d, alert }: { n: ReactNode; l: string; d?: string; alert?: boolean }) => <div className={`kpi ${alert ? 'alert' : ''}`}><span className="n">{n}</span><span className="l">{l}</span>{d && <span className="d">{d}</span>}</div>;
function Table({ cols, rows, empty }: { cols: string[]; rows: ReactNode[][]; empty: string }) {
  return rows.length === 0 ? <Empty title="Sin resultados">{empty}</Empty> : <div className="tablewrap"><table><thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead><tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>)}</tbody></table></div>;
}
function Spark({ series, k, cls }: { series: R[]; k: string; cls: string }) {
  const max = Math.max(1, ...series.map((p) => p[k])), pts = series.map((p, i) => `${(i / Math.max(1, series.length - 1)) * 300},${58 - (p[k] / max) * 52}`).join(' ');
  return <svg className="spark" viewBox="0 0 300 64" role="img" aria-label={`Evolución de ${k}`} preserveAspectRatio="none"><polyline className={cls} points={pts} /></svg>;
}
function useAction() {
  const toast = useToast();
  return async (p: Promise<unknown> | (() => Promise<unknown>), ok: string) => { try { await (typeof p === 'function' ? p() : p); toast(ok); refreshAll(); } catch (e) { toast((e as Error).message, 'err'); } };
}
const Err = ({ r }: { r: { error?: string; reload: () => void } }) => (r.error ? <ErrorBanner message={r.error} retry={r.reload} /> : null);

// ───────── Ejecutiva ─────────
export function Executive() {
  const r = useResource<R>('/dashboard/executive', 15000), d = r.data;
  return (
    <Page title="Vista ejecutiva" lede="Cifras calculadas solo con los datos ingeridos: si no hay datos, no hay puntuación.">
      <Err r={r} />{!d ? <Skeleton rows={4} /> : <>
        <div className="kpis">
          <Kpi n={d.risk.score ?? '—'} l="Riesgo global" d={d.risk.level} alert={(d.risk.score ?? 0) >= 50} />
          <Kpi n={d.assets.total} l="Activos" d={`${d.assets.internetFacing} expuestos a Internet`} />
          <Kpi n={d.vulnerabilities.immediate} l="Prioridad inmediata" d={`${d.vulnerabilities.open} abiertas · ${d.vulnerabilities.kev} KEV`} alert={d.vulnerabilities.immediate > 0} />
          <Kpi n={d.cases.active} l="Casos activos" d={`${d.cases.probableCorrelations} correlaciones probables`} />
          <Kpi n={d.identities.privileged} l="Identidades privilegiadas" d={`${d.identities.riskyConfirmed} con riesgo alto confirmado`} />
          <Kpi n={d.exposures.confirmed} l="Exposiciones confirmadas" d={`${d.exposures.suspected} sospechadas`} />
        </div>
        <div className="split findings">
          <section className="panel"><header><h2>Por qué este riesgo</h2></header><div className="body stack">
            {d.risk.factors.map((f: R) => <div key={f.name}><div style={{ display: 'flex', justifyContent: 'space-between' }}><span>{f.name}</span><b>{f.points}/{f.max}</b></div><div className="riskbar"><i style={{ width: `${(f.points / f.max) * 100}%` }} /></div></div>)}
            <p className="muted">{d.limitations.join(' ')}</p></div></section>
          <section className="panel"><header><h2>Riesgos prioritarios</h2></header>
            {d.priorities.length === 0 ? <Empty title="Nada urgente">No hay vulnerabilidades abiertas priorizadas.</Empty> : <ul className="list">{d.priorities.map((p: R) => <li key={p.id}><div className="row" style={{ cursor: 'default' }}><span className="t">{p.cve ?? p.title} <span className={`chip lvl-${p.priority}`}>{p.priority} {p.score}</span></span><span className="m">{p.explanation}</span></div></li>)}</ul>}</section>
        </div>
        <div className="split findings" style={{ marginTop: 18 }}>
          <section className="panel"><header><h2>Evolución (30 días)</h2></header><div className="body"><Spark series={d.trend.series} k="vulnerabilities" cls="v" /><Spark series={d.trend.series} k="cases" cls="c" /><Spark series={d.trend.series} k="signals" cls="s" /><p className="muted">Rojo: vulnerabilidades nuevas · Índigo: casos · Gris: señales.</p></div></section>
          <section className="panel"><header><h2>Integraciones</h2><a href="#/integraciones">Ver todas</a></header><div className="body stack">
            {d.integrations.connectors.total === 0 ? <p className="muted">Ningún conector configurado.</p> : Object.entries(d.integrations.connectors.byStatus).map(([k, v]) => <div key={k}><span className={`state ${k}`}>{STATE_LABEL[k] ?? k}</span> {String(v)}</div>)}
            {d.integrations.connectors.failing.map((f: R) => <p key={f.name} style={{ color: 'var(--risk)' }}>{f.name}: {f.error}</p>)}
            <p className="muted">Canales de notificación: {d.integrations.notificationChannels.length}. Aprobaciones pendientes: {d.approvalsPending}.</p></div></section>
        </div></>}
    </Page>
  );
}

// ───────── CTEM ─────────
export function Ctem() {
  const [tab, setTab] = useState<'assets' | 'vulns' | 'exp' | 'paths'>('vulns'), [q, setQ] = useState(''), [off, setOff] = useState(0), [prio, setPrio] = useState('');
  const path = tab === 'assets' ? `/inventory/assets?limit=${LIMIT}&offset=${off}&q=${encodeURIComponent(q)}` : tab === 'vulns' ? `/vulns?limit=${LIMIT}&offset=${off}&q=${encodeURIComponent(q)}&status=open,in_progress${prio ? `&priority=${prio}` : ''}` : tab === 'exp' ? `/exposures/findings?limit=${LIMIT}&offset=${off}&status=open` : '/ctem/attack-paths';
  const r = useResource<Paged | R[]>(path), act = useAction(), { api, me } = useSession();
  const items: R[] = Array.isArray(r.data) ? r.data : r.data?.items ?? [], total = Array.isArray(r.data) ? items.length : r.data?.total ?? 0;
  const [name, setName] = useState('');
  return (
    <Page title="CTEM" lede="Activos, vulnerabilidades priorizadas por contexto, superficie de ataque y rutas teóricas.">
      <Tabs tabs={[['vulns', 'Vulnerabilidades'], ['assets', 'Activos'], ['exp', 'Exposición'], ['paths', 'Rutas de ataque']]} value={tab} onChange={(t) => { setTab(t); setOff(0); setQ(''); }} />
      <div className="filters" style={{ marginTop: 14 }}>
        {(tab === 'vulns' || tab === 'assets') && <input type="search" aria-label="Buscar" placeholder="Buscar" value={q} onChange={(e) => { setQ(e.target.value); setOff(0); }} style={{ maxWidth: 260 }} />}
        {tab === 'vulns' && <select aria-label="Prioridad" value={prio} onChange={(e) => { setPrio(e.target.value); setOff(0); }} style={{ width: 'auto' }}><option value="">Toda prioridad</option><option value="immediate">Inmediata</option><option value="high">Alta</option><option value="medium">Media</option></select>}
        {tab === 'assets' && me.role !== 'viewer' && <form className="filters" style={{ margin: 0 }} onSubmit={(e) => { e.preventDefault(); void act(api.post('/inventory/assets', { type: 'domain', identifier: name, internetFacing: true, source: 'consola' }), 'Activo registrado'); setName(''); }}><input type="text" aria-label="Dominio" placeholder="nuevo.dominio.com" value={name} onChange={(e) => setName(e.target.value)} required /><button className="btn primary small">Añadir dominio</button></form>}
      </div>
      <Err r={r} />
      <section className="panel">{!r.data ? <Skeleton rows={5} /> : tab === 'vulns' ? (
        <Table cols={['Vulnerabilidad', 'Prioridad', 'Gravedad', 'CVSS / EPSS', 'Confianza', 'Vence']} empty="No hay vulnerabilidades abiertas." rows={items.map((v) => [<><b>{v.cve ?? v.title}</b><div className="muted">{v.source}</div><details className="why"><summary>¿Por qué esta prioridad?</summary><p>{v.priority?.explanation}</p></details></>, v.priority ? <span className={`chip lvl-${v.priority.level}`}>{v.priority.level} · {v.priority.score}</span> : '—', sev(v.severity), `${v.cvss?.score ?? 'n/d'} / ${v.epss ? v.epss.score.toFixed(2) : 'n/d'}${v.kev ? ' · KEV' : ''}`, v.confidence, v.dueDate?.slice(0, 10) ?? ''])} />
      ) : tab === 'assets' ? (
        <Table cols={['Activo', 'Tipo', 'Criticidad', 'Propiedad', 'Visto']} empty="No hay activos. Añade uno o conecta una fuente." rows={items.map((a) => [<><b>{a.name}</b>{a.internetFacing && <span className="chip warn" style={{ marginLeft: 6 }}>Internet</span>}<div className="muted">{a.source}</div></>, a.type, a.criticality, a.ownership.status === 'verified' ? <span className="chip ok">verificada ({a.ownership.method})</span> : <span className="chip">sin verificar</span>, ago(a.lastSeen)])} />
      ) : tab === 'exp' ? (
        <Table cols={['Exposición', 'Gravedad', 'Confianza', 'Evidencia', 'Visto']} empty="Sin exposiciones abiertas." rows={items.map((e) => [<b>{e.title}</b>, sev(e.severity), `${e.confidence} (${e.seen}×)`, e.evidence.join('; '), ago(e.lastSeen)])} />
      ) : items.length === 0 ? <Empty title="Sin rutas">Registra relaciones entre activos e identidades para calcular rutas teóricas.</Empty> : (
        <ul className="list">{items.map((p) => <li key={p.id}><div className="row" style={{ cursor: 'default' }}><span className="pathline">{p.nodes.map((n: R, i: number) => <span key={n.id}>{i > 0 && <span className="arrow">—{p.edges[i - 1].kind}→ </span>}<span className="chip">{n.name}</span></span>)}</span><span className="m"><span className="chip warn">{p.status === 'theoretical' ? 'teórica' : 'corroborada por alertas'}</span><span>confianza {p.confidence}</span><span>{p.impact}</span></span><span className="muted">{p.notes.join(' ')}</span></div></li>)}</ul>)}
        {tab !== 'paths' && <Pager total={total} offset={off} set={setOff} />}</section>
    </Page>
  );
}

// ───────── IAM ─────────
export function Iam() {
  const [off, setOff] = useState(0), [priv, setPriv] = useState(''), [q, setQ] = useState('');
  const list = useResource<Paged>(`/iam/identities?limit=${LIMIT}&offset=${off}&q=${encodeURIComponent(q)}${priv ? `&privileged=${priv}` : ''}`), sum = useResource<R>('/iam/summary'), risks = useResource<R[]>('/iam/risks');
  return (
    <Page title="Identidades" lede="Cuentas humanas y de servicio, privilegios, inactividad y riesgos de acceso. Lo que no se pudo verificar se marca así.">
      <Err r={list} />
      {sum.data && <div className="kpis"><Kpi n={sum.data.total} l="Identidades" d={`${sum.data.human} humanas · ${sum.data.service} de servicio`} /><Kpi n={sum.data.privileged} l="Privilegiadas" /><Kpi n={sum.data.inactive} l="Inactivas confirmadas" /><Kpi n={sum.data.unverified} l="Sin datos para verificar" /><Kpi n={(sum.data.risksBySeverity.critical ?? 0) + (sum.data.risksBySeverity.high ?? 0)} l="Riesgos altos/críticos" alert /></div>}
      <div className="filters"><input type="search" aria-label="Buscar" placeholder="Buscar identidad" value={q} onChange={(e) => { setQ(e.target.value); setOff(0); }} style={{ maxWidth: 260 }} /><select aria-label="Privilegio" value={priv} onChange={(e) => { setPriv(e.target.value); setOff(0); }} style={{ width: 'auto' }}><option value="">Todas</option><option value="true">Privilegiadas</option><option value="false">No privilegiadas</option></select></div>
      <div className="split findings">
        <section className="panel">{!list.data ? <Skeleton /> : <><Table cols={['Identidad', 'Proveedor', 'MFA', 'Última actividad']} empty="Sin identidades. Conecta Entra, Okta o Google Workspace." rows={list.data.items.map((i) => [<><b>{i.name}</b> {i.privileged && <span className="chip risk">privilegiada</span>}<div className="muted">{i.kind} · {i.status}</div></>, i.provider, i.mfaEnabled === undefined ? 'desconocido' : i.mfaEnabled ? 'sí' : <b style={{ color: 'var(--risk)' }}>NO</b>, i.lastActivityAt ? ago(i.lastActivityAt) : 'desconocida'])} /><Pager total={list.data.total} offset={off} set={setOff} /></>}</section>
        <section className="panel"><header><h2>Riesgos de acceso</h2></header>{!risks.data ? <Skeleton /> : risks.data.filter((x) => x.code !== 'privileged').length === 0 ? <Empty title="Sin riesgos">No se detectaron riesgos con los datos disponibles.</Empty> : <ul className="list">{risks.data.filter((x) => x.code !== 'privileged').slice(0, 40).map((x, i) => <li key={i}><div className="row" style={{ cursor: 'default' }}><span className="t">{sev(x.severity)} {x.code}</span><span className="m">{x.detail}{x.confidence === 'unverified' && ' · sin verificar'}</span></div></li>)}</ul>}<p className="muted" style={{ padding: '0 16px 12px' }}>Solo propone: ningún permiso se cambia desde aquí.</p></section>
      </div>
    </Page>
  );
}

// ───────── SOAR ─────────
export function Soar() {
  const [tab, setTab] = useState<'approvals' | 'playbooks' | 'runs' | 'auto'>('approvals'), act = useAction(), { api, me } = useSession();
  const pb = useResource<R[]>('/soar/playbooks'), runs = useResource<R[]>('/soar/runs', 8000), ap = useResource<R[]>('/soar/approvals', 5000), auto = useResource<R>('/soar/automation');
  const [reason, setReason] = useState('');
  const canApprove = me.role === 'approver' || me.role === 'admin', admin = me.role === 'admin';
  return (
    <Page title="Orquestación (SOAR)" lede="Los playbooks proponen; una persona firma. El modo AUTOMATIZADO está apagado salvo que un administrador lo active.">
      <Err r={pb} />
      <Tabs tabs={[['approvals', `Aprobaciones (${ap.data?.length ?? 0})`], ['playbooks', 'Playbooks'], ['runs', 'Ejecuciones'], ['auto', 'Automatización']]} value={tab} onChange={setTab} />
      <section className="panel" style={{ marginTop: 14 }}>
        {tab === 'approvals' && (!ap.data ? <Skeleton /> : ap.data.length === 0 ? <Empty title="Nada espera tu firma">Las acciones propuestas por playbooks aparecerán aquí; no se ejecutan sin firma.</Empty> : <ul className="list">{ap.data.map((a) => <li key={a.approvalId}><div className="row" style={{ cursor: 'default' }}>
          <span className="t">{a.action} <span className={`chip ${a.riskLevel === 'high' ? 'risk' : 'warn'}`}>riesgo {a.riskLevel}</span></span><span className="m"><span>playbook {a.playbook}</span><span>solicitado {ago(a.requestedAt)} por {a.requestedBy}</span></span><code className="muted">{JSON.stringify(a.params)}</code>
          <div className="row-actions"><HoldToSign label="Mantén para aprobar" disabled={!canApprove} onConfirm={() => void act(api.post(`/approvals/${a.approvalId}/decision`, { decision: 'approved', comment: 'Aprobado desde la consola' }), 'Aprobada y ejecutada en el laboratorio')} /><button className="btn" disabled={!canApprove} onClick={() => void act(api.post(`/approvals/${a.approvalId}/decision`, { decision: 'rejected', comment: 'Rechazada desde la consola' }), 'Rechazada')}>Rechazar</button></div></div></li>)}</ul>)}
        {tab === 'playbooks' && (!pb.data ? <Skeleton /> : <><div className="body">{admin || me.role === 'analyst' ? <button className="btn small" onClick={() => void act(api.post('/soar/playbooks/install-defaults'), 'Playbooks base instalados')}>Instalar playbooks base</button> : null}</div>{pb.data.length === 0 ? <Empty title="Sin playbooks">Instala los playbooks base o publica uno propio.</Empty> : <Table cols={['Playbook', 'Disparador', 'Modo', 'Riesgo', 'Estado']} empty="" rows={pb.data.map((p) => [<><b>{p.name}</b><div className="muted">{p.key} v{p.version}</div></>, p.trigger.type, <>{p.effectiveMode}{p.effectiveMode !== p.mode && <span className="muted"> (pide {p.mode})</span>}</>, p.riskLevel, <button key="t" className="btn small" disabled={!admin} onClick={() => void act(api.post(`/soar/playbooks/${p.key}/state`, { enabled: !p.enabled }), p.enabled ? 'Deshabilitado' : 'Habilitado')}>{p.enabled ? 'Habilitado' : 'Deshabilitado'}</button>])} />}</>)}
        {tab === 'runs' && (!runs.data ? <Skeleton /> : <Table cols={['Cuándo', 'Playbook', 'Modo', 'Estado', 'Pasos']} empty="Sin ejecuciones todavía." rows={runs.data.map((r) => [clock(r.createdAt), `${r.playbookKey} v${r.playbookVersion}`, r.effectiveMode, r.status, r.steps.map((s: R) => `${s.action}:${s.status}`).join(' → ')])} />)}
        {tab === 'auto' && (!auto.data ? <Skeleton /> : <div className="body stack">
          <dl className="kv"><dt>Techo de automatización</dt><dd>{auto.data.ceiling}</dd><dt>AUTOMATIZADO permitido</dt><dd>{auto.data.automatedEnabled ? 'sí' : 'no (por defecto)'}</dd><dt>Acciones automáticas</dt><dd>{auto.data.allowedAutoActions.join(', ') || 'ninguna'}</dd><dt>Máx. por hora</dt><dd>{auto.data.maxActionsPerHour}</dd><dt>Kill switch</dt><dd>{auto.data.killSwitch ? `ACTIVADO: ${auto.data.killReason}` : 'apagado'}</dd></dl>
          {canApprove && <form className="formgrid" onSubmit={(e) => { e.preventDefault(); void act(api.post('/soar/kill-switch', { on: !auto.data!.killSwitch, reason }), auto.data!.killSwitch ? 'Kill switch liberado' : 'Kill switch activado'); }}><label className="field"><span>Motivo (mín. 5 caracteres)</span><input type="text" value={reason} onChange={(e) => setReason(e.target.value)} required minLength={5} /></label><button className="btn primary">{auto.data.killSwitch ? 'Liberar kill switch' : 'Activar kill switch'}</button></form>}
        </div>)}
      </section>
    </Page>
  );
}

// ───────── Casos ─────────
export function Cases({ id }: { id?: string }) {
  const [off, setOff] = useState(0), [st, setSt] = useState('new,investigating,contained,remediating'), list = useResource<Paged>(`/cases?limit=${LIMIT}&offset=${off}&status=${st}`, 10000);
  const detail = useResource<R>(id ? `/cases/${id}` : null), act = useAction(), { api, me } = useSession(), [note, setNote] = useState('');
  const c = detail.data?.case, canWrite = me.role !== 'viewer';
  const NEXT: Record<string, string[]> = { new: ['investigating'], investigating: ['contained', 'remediating', 'resolved'], contained: ['remediating', 'resolved'], remediating: ['resolved'], resolved: ['closed'], closed: [] };
  return (
    <Page title="Casos" lede="Gestión de incidentes con línea de tiempo, evidencia con cadena de custodia y acciones registradas.">
      <div className="filters"><select aria-label="Estado" value={st} onChange={(e) => { setSt(e.target.value); setOff(0); }} style={{ width: 'auto' }}><option value="new,investigating,contained,remediating">Activos</option><option value="resolved,closed">Cerrados</option><option value="">Todos</option></select></div>
      <Err r={list} />
      <div className="split findings">
        <section className="panel">{!list.data ? <Skeleton /> : list.data.items.length === 0 ? <Empty title="Sin casos">Se abren solos desde correlaciones o playbooks, o a mano con POST /api/v1/cases.</Empty> : <><ul className="list">{list.data.items.map((k) => <li key={k.id}><a className="row" aria-current={k.id === id} href={`#/casos/${k.id}`}><span className="t">#{k.number} {k.name}</span><span className="m">{sev(k.severity)}<span className="chip">{k.status}</span><span>{ago(k.openedAt)}</span>{k.source !== 'manual' && <span className="chip sign">{k.source}</span>}</span></a></li>)}</ul><Pager total={list.data.total} offset={off} set={setOff} /></>}</section>
        {!id ? <section className="panel"><Empty title="Elige un caso">Verás su línea de tiempo, evidencia y recomendaciones.</Empty></section> : !detail.data || !c ? <Skeleton /> : (
          <article className="panel"><header><h2>#{c.number} {c.name}</h2>{sev(c.severity)}</header><div className="body stack">
            <p>{c.description}</p>
            <div className="row-actions">{NEXT[c.status].map((s) => <button key={s} className="btn small" disabled={!canWrite} onClick={() => void act(api.post(`/cases/${c.id}/status`, { status: s, note: s === 'resolved' || s === 'closed' ? note || 'Resuelto desde la consola' : undefined }), `Estado: ${s}`)}>→ {s}</button>)}</div>
            <section><h3 className="muted" style={{ fontSize: 13 }}>Evidencia</h3>{detail.data.evidence.length === 0 ? <p className="muted">Sin evidencia adjunta.</p> : detail.data.evidence.map((e: R) => <div key={e.id} className="ev">{e.name} · {e.type} · sha256 <code>{e.sha256.slice(0, 16)}…</code></div>)}</section>
            {c.recommendations.length > 0 && <section><h3 className="muted" style={{ fontSize: 13 }}>Recomendaciones (no ejecutadas)</h3><ul>{c.recommendations.map((r: string) => <li key={r}>{r}</li>)}</ul></section>}
            <section><h3 className="muted" style={{ fontSize: 13 }}>Línea de tiempo</h3><ul className="timeline">{c.timeline.map((t: R) => <li key={t.id}><time>{clock(t.at)}</time><span><b>{t.actor}</b> · {t.kind}: {t.text}</span></li>)}</ul></section>
            {canWrite && <form className="formgrid" onSubmit={(e) => { e.preventDefault(); void act(api.post(`/cases/${c.id}/comments`, { text: note }), 'Comentario añadido'); setNote(''); }}><label className="field"><span>Comentario / nota</span><input type="text" value={note} onChange={(e) => setNote(e.target.value)} required /></label><button className="btn">Comentar</button></form>}
          </div></article>)}
      </div>
    </Page>
  );
}

// ───────── Integraciones ─────────
export function Integrations() {
  const r = useResource<R[]>('/connectors', 10000), ch = useResource<R[]>('/notifications/channels'), act = useAction(), { api, me } = useSession(), admin = me.role === 'admin';
  return (
    <Page title="Integraciones" lede="El estado mostrado es el real: una integración solo figura como conectada tras una prueba o sincronización exitosa.">
      <Err r={r} />
      <section className="panel">{!r.data ? <Skeleton /> : r.data.length === 0 ? <Empty title="Sin conectores">Configura AWS, Azure, GCP, CrowdStrike, Defender, Wazuh o un proveedor de identidad con POST /api/v1/connectors.</Empty> : <ul className="list">{r.data.map((c) => <li key={c.id}><div className="row" style={{ cursor: 'default' }}>
        <span className="t">{c.name} <span className="muted">({c.kind})</span> <span className={`state ${c.status}`}>{STATE_LABEL[c.status]}</span></span>
        <span className="m"><span>{VERIF_LABEL[c.verification]}</span>{c.lastSyncAt && <span>última sincronización {ago(c.lastSyncAt)}</span>}{c.expiryWarning && <span className="chip warn">credenciales caducan en {c.credentialsExpireInDays} días</span>}</span>
        {c.lastError && <span style={{ color: 'var(--risk)' }}>{c.lastError}</span>}
        <details className="why"><summary>Permisos mínimos que pide y actividad</summary><p>{c.requiredPermissions.join(' · ')}</p><p>{c.activity.slice(0, 5).map((a: R) => `${clock(a.at)} ${a.text}`).join(' | ')}</p></details>
        {admin && <div className="row-actions"><button className="btn small" disabled={!c.hasCredentials || !c.enabled} onClick={() => void act(api.post(`/connectors/${c.id}/test`), 'Prueba ejecutada')}>Probar</button><button className="btn small" disabled={!c.hasCredentials || !c.enabled} onClick={() => void act(api.post(`/connectors/${c.id}/sync`), 'Sincronización completada')}>Sincronizar</button><button className="btn small" onClick={() => void act(api.post(`/connectors/${c.id}/${c.enabled ? 'disable' : 'enable'}`), c.enabled ? 'Deshabilitado' : 'Habilitado')}>{c.enabled ? 'Deshabilitar' : 'Habilitar'}</button></div>}</div></li>)}</ul>}</section>
      <section className="panel" style={{ marginTop: 18 }}><header><h2>Canales de notificación</h2></header>{!ch.data ? <Skeleton rows={2} /> : <Table cols={['Canal', 'Tipo', 'Severidad mínima', 'Estado']} empty="Sin canales (email, Slack o Teams)." rows={ch.data.map((c) => [c.name, c.kind, c.minSeverity, c.enabled ? 'activo' : 'deshabilitado'])} />}</section>
    </Page>
  );
}

// ───────── Informes ─────────
export function Reports() {
  const r = useResource<R[]>('/reports'), act = useAction(), { api, me } = useSession(), [kind, setKind] = useState('executive'), [caseId, setCaseId] = useState('');
  const KIND: Record<string, string> = { executive: 'Ejecutivo', technical: 'Técnico', incident: 'Incidente', identity: 'Identidades' };
  return (
    <Page title="Informes" lede="PDF con organización, fecha, periodo y limitaciones de los datos. No se inventan métricas ausentes.">
      {me.role !== 'viewer' && <form className="formgrid panel" style={{ padding: 16, marginBottom: 18 }} onSubmit={(e) => { e.preventDefault(); void act(api.post('/reports', { kind, caseId: kind === 'incident' ? caseId : undefined }), 'Informe generado'); }}>
        <label className="field"><span>Tipo</span><select value={kind} onChange={(e) => setKind(e.target.value)}>{Object.entries(KIND).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        {kind === 'incident' && <label className="field"><span>ID del caso</span><input type="text" value={caseId} onChange={(e) => setCaseId(e.target.value)} required /></label>}
        <button className="btn primary">Generar PDF</button></form>}
      <Err r={r} />
      <section className="panel">{!r.data ? <Skeleton /> : <Table cols={['Informe', 'Generado', 'Por', 'Huella', '']} empty="Aún no hay informes." rows={r.data.map((x) => [KIND[x.kind] ?? x.kind, clock(x.generatedAt), x.generatedBy, <code key="h">{x.sha256.slice(0, 12)}…</code>, <button key="d" className="btn small" onClick={() => void act(api.download(`/reports/${x.id}/pdf`, `sentinelmesh-${x.kind}.pdf`), 'Descarga iniciada')}>Descargar</button>])} />}</section>
    </Page>
  );
}
