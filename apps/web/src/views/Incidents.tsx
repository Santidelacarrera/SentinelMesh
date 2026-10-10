import { Fragment, useState } from 'react';
import { go, useResource } from '../api';
import { Empty, ErrorBanner, Hash, Page, Sev, Skeleton } from '../ui/kit';
import { ago, clock } from '../lib/format';
import type { Forensics, Incident } from '../types';

const KIND: Record<string, string> = { brute_force: 'Fuerza bruta', request_spike: 'Pico de peticiones' };

export function Incidents({ id }: { id?: string }) {
  const res = useResource<Incident[]>('/incidents', 6000), items = res.data ?? [], cur = items.find((i) => i.id === id) ?? items[0];
  return (
    <Page title="Incidentes" lede="La evidencia se congela en el instante de la alerta, antes de cualquier contención.">
      {res.error && <ErrorBanner message={res.error} retry={res.reload} />}
      <div className="split">
        <section className="panel">{!res.data ? <Skeleton rows={4} /> : items.length === 0 ? <Empty title="Sin incidentes">Las anomalías enviadas por tu API Gateway a /incidents/trigger que superen el umbral abrirán uno.</Empty> : (
          <ul className="list">{items.map((i) => <li key={i.id}><button className="row" aria-current={cur?.id === i.id} onClick={() => go(`/incidentes/${i.id}`)}>
            <span className="t">{KIND[i.anomaly?.kind ?? ''] ?? 'Anomalía'} contra {i.target}</span><span className="m"><Sev level={i.severity} /><span>{ago(i.createdAt)}</span><span className={`chip ${i.status === 'contained' ? 'ok' : 'sign'}`}>{i.status === 'contained' ? 'Contenido' : i.status === 'awaiting_approval' ? 'Contención pendiente' : 'Abierto'}</span></span></button></li>)}</ul>)}</section>
        {cur ? <Detail key={cur.id} i={cur} /> : <section className="panel"><Empty title="Elige un incidente" /></section>}
      </div>
    </Page>
  );
}

function Detail({ i }: { i: Incident }) {
  const f = useResource<Forensics>(i.executionId ? `/executions/${i.executionId}/forensics` : null);
  const [hl, setHl] = useState<string>();
  const lines = (f.data?.incident.summary ?? '').split('\n').filter(Boolean);
  const evidence = f.data ? [['ev-metrics', JSON.stringify(f.data.evidence.metrics)], ['ev-container', JSON.stringify(f.data.evidence.containerState)], ...f.data.evidence.logs.map((l, n) => [`ev-log-${n + 1}`, l])] : [];
  return (
    <article className="panel"><header><h2>{i.target}</h2><Sev level={i.severity} /></header>
      <div className="body stack">
        {i.anomaly && <p><b>{i.anomaly.count.toLocaleString('es')}</b> peticiones en {i.anomaly.windowSec} s desde <code>{i.anomaly.source}</code> · {KIND[i.anomaly.kind]}</p>}
        {i.status === 'awaiting_approval' && <p className="note">El aislamiento del servicio está propuesto y espera firma. <a href="#/decisiones">Ir a Decisiones</a></p>}
        {f.error ? <ErrorBanner message={f.error} retry={f.reload} /> : !f.data ? <Skeleton rows={4} /> : (<>
          <p><span className="chip ok">Integridad {f.data.snapshot.integrity === 'verified' ? 'verificada' : f.data.snapshot.integrity}</span> <span className="muted">congelado {clock(f.data.snapshot.capturedAt)} · sha256 </span><Hash value={f.data.snapshot.sha256} n={16} /></p>
          <section><h3 className="muted" style={{ fontSize: 13, marginBottom: 6 }}>Resumen: cada línea cita su evidencia</h3>
            <ul className="list">{lines.map((l, n) => { const m = /^- \[(ev-[\w-]+)\] (.*)$/.exec(l); return <li key={n} style={{ padding: '4px 0' }}>{m ? <><button className="cite" onClick={() => { setHl(m[1]); document.getElementById(m[1])?.scrollIntoView({ block: 'nearest' }); }}>{m[1]}</button> {m[2].length > 90 ? m[2].slice(0, 90) + '…' : m[2]}</> : l}</li>; })}</ul></section>
          <section><h3 className="muted" style={{ fontSize: 13, marginBottom: 6 }}>Evidencia congelada (secretos redactados)</h3>
            <div style={{ display: 'grid', gap: 6 }}>{evidence.map(([k, v]) => <Fragment key={k}><div id={k} className={`ev ${hl === k ? 'hl' : ''}`}><span className="muted">{k} </span>{v}</div></Fragment>)}</div></section></>)}
      </div></article>
  );
}
