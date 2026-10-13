import { useEffect, useState } from 'react';
import { go, useResource, useSession, useToast } from '../api';
import { Empty, ErrorBanner, Hash, HoldToSign, Page, Skeleton, Tabs } from '../ui/kit';
import { ago, clock, stepLabel, WORKFLOW_LABEL } from '../lib/format';
import { describeImpact, KIND_LABEL } from '../lib/impact';
import { diffStats, parseDiff } from '../lib/diff';
import type { Approval } from '../types';

export function DiffView({ diff }: { diff: string }) {
  const lines = parseDiff(diff), st = diffStats(lines);
  return <div><div className="diff" role="figure" aria-label={`Cambio propuesto: ${st.added} líneas añadidas, ${st.removed} quitadas`}>
    {lines.map((l, i) => <div key={i} className={l.kind}><span className="n">{l.n ?? ''}</span><span className="g">{l.kind === 'add' ? '+' : l.kind === 'del' ? '−' : ''}</span><span>{l.text || ' '}</span></div>)}
  </div><p className="muted" style={{ marginTop: 6 }}>{st.added} añadidas · {st.removed} quitadas</p></div>;
}

export function Decisions({ id }: { id?: string }) {
  const list = useResource<Approval[]>('/approvals', 5000);
  const items = list.data ?? [], pending = items.filter((a) => a.status === 'pending'), done = items.filter((a) => a.status !== 'pending');
  const current = items.find((a) => a.id === id) ?? pending[0] ?? done[0];
  const currentId = current?.id;
  useEffect(() => { if (!id && currentId) history.replaceState(null, '', `#/decisiones/${currentId}`); }, [id, currentId]);
  return (
    <Page title="Decisiones" lede="Nada destructivo se ejecuta sin una firma. Revisa el cambio exacto y firma, o recházalo con un motivo.">
      {list.error && <ErrorBanner message={list.error} retry={list.reload} />}
      <div className="split">
        <section className="panel" aria-label="Lista de decisiones">
          {!list.data ? <Skeleton rows={5} /> : items.length === 0 ? <Empty title="Sin decisiones">Cuando una remediación necesite aprobación, aparecerá aquí con su cambio exacto.</Empty> : (
            <ul className="list">
              {[...pending, ...done].map((a) => (
                <li key={a.id}><button className={`row ${a.status === 'pending' ? 'gate' : ''}`} aria-current={current?.id === a.id} onClick={() => go(`/decisiones/${a.id}`)}>
                  <span className="t">{a.plan ? KIND_LABEL[a.plan.kind] : 'Cambio'} · {a.plan?.targetRef}</span>
                  <span className="m">{a.status === 'pending' ? <span className="chip sign">Espera tu firma</span> : a.status === 'approved' ? <span className="chip ok">Firmada</span> : <span className="chip risk">Rechazada</span>}<span>{ago(a.decidedAt ?? a.requestedAt)}</span></span>
                </button></li>))}
            </ul>)}
        </section>
        {current ? <WorkOrder key={current.id} a={current} onDone={list.reload} /> : <section className="panel"><Empty title="Elige una decisión" /></section>}
      </div>
    </Page>
  );
}

function WorkOrder({ a, onDone }: { a: Approval; onDone: () => void }) {
  const { api, me, refreshCounts } = useSession(), toast = useToast();
  const [tab, setTab] = useState<'diff' | 'tf' | 'params'>('diff'), [comment, setComment] = useState(''), [busy, setBusy] = useState(false), [err, setErr] = useState('');
  const plan = a.plan, ex = a.execution;
  if (!plan) return <section className="panel"><Empty title="Plan no disponible" /></section>;
  const impact = describeImpact(plan), own = ex?.requestedBy === me.userId, canDecide = me.role === 'approver' || me.role === 'admin';
  const blocked = a.status !== 'pending' ? null : !canDecide ? 'Tu rol no puede firmar. Hace falta el rol approver.' : own ? 'Solicitaste este cambio tú: otra persona con rol approver debe firmarlo.' : null;
  const decide = async (decision: 'approved' | 'rejected') => {
    if (decision === 'rejected' && comment.trim().length < 3) { setErr('Explica brevemente por qué lo rechazas.'); return; }
    setBusy(true); setErr('');
    try { await api.post(`/approvals/${a.id}/decision`, { decision, comment: comment.trim() || undefined }); toast(decision === 'approved' ? 'Firmada. La ejecución continúa.' : 'Rechazada. No se ha cambiado nada.'); refreshCounts(); onDone(); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <article className="panel order" aria-labelledby="wo-h">
      <div className="order-head">
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}><span className="chip sign">{KIND_LABEL[plan.kind]}</span><span className={`chip ${impact.reversible ? 'badge-rev' : 'badge-irrev'}`}>{impact.reversible ? 'Reversible' : 'Irreversible'}</span>
          {a.finding && <a className="chip" href={`#/hallazgos?id=${a.finding.id}`}>Origen: {a.finding.title}</a>}</div>
        <h2 id="wo-h">{impact.headline}</h2>
        <div className="order-meta"><span>Solicitado por <b>{ex?.requestedBy ?? '—'}</b> {ago(a.requestedAt)}</span>{ex && <span>{WORKFLOW_LABEL[ex.workflowKey] ?? ex.workflowKey}</span>}{ex?.incidentId && <a href="#/incidentes">Ver incidente</a>}</div>
      </div>
      <section><h3>Qué ocurrirá si firmas</h3>
        <div className="prose"><ul>{impact.effects.map((e, i) => <li key={i}>{e}</li>)}</ul><p style={{ marginTop: 8 }} className="muted">{impact.reversal}</p></div></section>
      <section><h3>Cambio exacto</h3>
        <Tabs tabs={[['diff', 'Diferencias'], ['tf', 'Terraform'], ['params', 'Parámetros']]} value={tab} onChange={setTab} />
        {tab === 'diff' && <DiffView diff={plan.diff} />}
        {tab === 'tf' && (plan.terraform ? <pre className="diff" style={{ padding: 12, margin: 0, whiteSpace: 'pre-wrap' }}>{plan.terraform}</pre> : <p className="muted">Este cambio no genera Terraform.</p>)}
        {tab === 'params' && <pre className="diff" style={{ padding: 12, margin: 0, whiteSpace: 'pre-wrap' }}>{JSON.stringify(plan.params, null, 2)}</pre>}
        <div className="hashbox"><span>Tu firma queda ligada a este plan:</span><Hash value={plan.planHash} n={16} /><span className="muted">Si el plan cambiara después, la ejecución se detiene.</span></div></section>
      {ex && <section><h3>Estado de la ejecución</h3>
        <ol className="steps">{ex.steps.map((s) => { const gate = s.name === a.stepName; const cls = s.status === 'succeeded' ? 'done' : gate ? (a.status === 'rejected' ? 'failed' : 'gate') : s.status === 'failed' ? 'failed' : s.status === 'skipped' ? 'skipped' : '';
          return <li key={s.name} className={cls}><span className="dot" aria-hidden>{s.status === 'succeeded' ? '✓' : gate ? '✎' : s.status === 'failed' ? '!' : ''}</span>
            <div><div className="name">{stepLabel(s.name)}</div><div className="sub">{gate && a.status === 'pending' ? 'Pausado: espera una firma humana' : s.status === 'succeeded' ? 'Hecho' : s.status === 'skipped' ? 'Omitido' : s.status === 'failed' ? (s.error ?? 'Falló') : 'Pendiente'}</div></div>
            {s.destructive && <span className="chip warn">destructivo</span>}</li>; })}</ol></section>}
      {a.status === 'pending' ? (
        <div className="decide">
          {blocked && <p className="note" role="note">{blocked}</p>}
          {err && <p role="alert" style={{ color: 'var(--risk)' }}>{err}</p>}
          <div className="decide-row">
            <label className="field"><span className="sr">Comentario (obligatorio si rechazas)</span><textarea placeholder="Motivo (obligatorio al rechazar)" value={comment} onChange={(e) => setComment(e.target.value)} disabled={!!blocked || busy} maxLength={2000} aria-label="Comentario (obligatorio si rechazas)" /></label>
            <button className="btn" disabled={!!blocked || busy} onClick={() => decide('rejected')}>Rechazar</button>
            <HoldToSign label={impact.reversible ? 'Mantén pulsado para firmar' : 'Mantén pulsado para firmar (irreversible)'} disabled={!!blocked || busy} onConfirm={() => decide('approved')} />
          </div>
        </div>
      ) : (
        <div className="decide"><div className={`signed ${a.status === 'rejected' ? 'rejected' : ''}`}>
          <b>{a.status === 'approved' ? 'Firmada' : 'Rechazada'} por {a.decidedBy}</b><span>{a.decidedAt && clock(a.decidedAt)}</span>{a.comment && <p>«{a.comment}»</p>}
          {a.signature && <span className="muted">Firma <Hash value={a.signature} n={20} /></span>}</div></div>
      )}
    </article>
  );
}
