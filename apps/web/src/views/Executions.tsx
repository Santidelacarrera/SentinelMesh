import { useState } from 'react';
import { go, useResource } from '../api';
import { Empty, ErrorBanner, Page, Skeleton } from '../ui/kit';
import { ago, clock, stepLabel, WORKFLOW_LABEL } from '../lib/format';
import type { Execution } from '../types';

const ST: Record<string, [string, string]> = { queued: ['En cola', ''], running: ['En curso', 'warn'], awaiting_approval: ['Espera firma', 'sign'], succeeded: ['Completada', 'ok'], failed: ['Fallida', 'risk'], rejected: ['Rechazada', 'risk'] };

export function Executions({ id }: { id?: string }) {
  const res = useResource<Execution[]>('/executions', 5000);
  const items = res.data ?? [], cur = items.find((e) => e.id === id) ?? items[0];
  return (
    <Page title="Ejecuciones" lede="Cada flujo es reanudable: si un worker cae, continúa donde lo dejó sin repetir efectos.">
      {res.error && <ErrorBanner message={res.error} retry={res.reload} />}
      <div className="split">
        <section className="panel">{!res.data ? <Skeleton rows={5} /> : items.length === 0 ? <Empty title="Sin ejecuciones">Inicia una rotación o una simulación para ver su progreso paso a paso.</Empty> : (
          <ul className="list">{items.map((e) => <li key={e.id}><button className="row" aria-current={cur?.id === e.id} onClick={() => go(`/ejecuciones/${e.id}`)}>
            <span className="t">{WORKFLOW_LABEL[e.workflowKey] ?? e.workflowKey}</span><span className="m"><span className={`chip ${ST[e.status][1]}`}>{ST[e.status][0]}</span><span>{ago(e.createdAt)}</span><span>por {e.context.requestedBy}</span></span></button></li>)}</ul>)}</section>
        {cur ? <Detail e={cur} /> : <section className="panel"><Empty title="Elige una ejecución" /></section>}
      </div>
    </Page>
  );
}

function Detail({ e }: { e: Execution }) {
  const [open, setOpen] = useState<string>();
  return (
    <article className="panel"><header><h2>{WORKFLOW_LABEL[e.workflowKey] ?? e.workflowKey} <span className="muted">v{e.workflowVersion}</span></h2><span className={`chip ${ST[e.status][1]}`}>{ST[e.status][0]}</span></header>
      <div className="body stack">
        <p className="muted">Iniciada {clock(e.createdAt)} por {e.context.requestedBy}. <code>{e.id}</code></p>
        <ol className="steps">{e.steps.map((s) => { const cls = s.status === 'succeeded' ? 'done' : s.status === 'awaiting_approval' ? 'gate' : s.status === 'failed' ? 'failed' : s.status === 'skipped' ? 'skipped' : '';
          return <li key={s.name} className={cls}><span className="dot" aria-hidden>{s.status === 'succeeded' ? '✓' : s.status === 'awaiting_approval' ? '✎' : s.status === 'failed' ? '!' : ''}</span>
            <div><div className="name">{stepLabel(s.name)}</div><div className="sub">{s.error ?? (s.status === 'awaiting_approval' ? 'Pausado hasta recibir una firma' : s.status === 'succeeded' ? `Hecho${s.finishedAt ? ' ' + ago(s.finishedAt) : ''}${s.attempts && s.attempts > 1 ? ` · ${s.attempts} intentos` : ''}` : s.status === 'skipped' ? 'Omitido' : 'Pendiente')}</div>
              {s.output && open === s.name && <pre className="diff" style={{ padding: 10, margin: '6px 0 0', whiteSpace: 'pre-wrap' }}>{JSON.stringify(s.output, null, 2)}</pre>}</div>
            <span style={{ display: 'flex', gap: 6 }}>{s.destructive && <span className="chip warn">destructivo</span>}{s.output && <button className="btn ghost" onClick={() => setOpen(open === s.name ? undefined : s.name)}>{open === s.name ? 'Ocultar' : 'Resultado'}</button>}</span></li>; })}</ol>
        {e.status === 'awaiting_approval' && <a className="btn sign" style={{ textDecoration: 'none', justifySelf: 'start' }} href="#/decisiones">Ir a Decisiones</a>}
      </div></article>
  );
}
