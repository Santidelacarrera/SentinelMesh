import { StrictMode, useCallback, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Api, Approval, Summary } from './api';
import './styles.css';

type Tab = 'exposure' | 'approvals' | 'forensics' | 'iam';

function DiffView({ diff }: { diff: string }) {
  return <pre className="diff">{diff.split('\n').map((l, i) => <div key={i} className={l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : ''}>{l || ' '}</div>)}</pre>;
}

function Exposure({ api }: { api: Api }) {
  const [s, setS] = useState<Summary>(); const [err, setErr] = useState('');
  useEffect(() => { api.call<Summary>('GET', '/exposures/summary').then(setS).catch((e) => setErr(e.message)); }, [api]);
  if (err) return <p className="err">{err}</p>; if (!s) return <p>Cargando…</p>;
  return <>
    <div className="cards">
      {(['critical', 'high', 'medium', 'low'] as const).map((k) => <div key={k} className={`card sev-${k}`}><b>{s.bySeverity[k] ?? 0}</b><span>{k}</span></div>)}
      <div className="card"><b>{s.totals.suppressed}</b><span>falsos positivos suprimidos</span></div>
      <div className="card"><b>{s.totals.secrets}</b><span>secretos expuestos</span></div>
    </div>
    <table><thead><tr><th>Hallazgo</th><th>Activo</th><th>Severidad</th><th>Base</th><th>Exposición</th></tr></thead>
      <tbody>{s.top.map((f) => <tr key={f.id}><td>{f.kind === 'secret' ? '🔑 ' : ''}{f.title}</td><td>{f.asset ?? '—'}</td><td><span className={`pill sev-${f.severity}`}>{f.severity}</span></td><td>{f.baseSeverity}</td><td>{f.exposureScore}</td></tr>)}</tbody></table>
  </>;
}

function Approvals({ api }: { api: Api }) {
  const [list, setList] = useState<Approval[]>([]); const [err, setErr] = useState(''); const [busy, setBusy] = useState('');
  const load = useCallback(() => api.call<Approval[]>('GET', '/approvals').then(setList).catch((e) => setErr(e.message)), [api]);
  useEffect(() => { load(); const t = setInterval(load, 4000); return () => clearInterval(t); }, [load]);
  const decide = async (id: string, decision: 'approved' | 'rejected') => {
    setBusy(id); setErr('');
    try { await api.call('POST', `/approvals/${id}/decision`, { decision }); await load(); } catch (e) { setErr((e as Error).message); } finally { setBusy(''); }
  };
  const pending = list.filter((a) => a.status === 'pending');
  return <>
    {err && <p className="err">{err}</p>}
    <h3>Pendientes ({pending.length})</h3>
    {pending.length === 0 && <p className="muted">Nada que aprobar.</p>}
    {pending.map((a) => <section key={a.id} className="approval">
      <header><b>{a.plan?.kind}</b> → {a.plan?.targetRef} <code>{a.planHash.slice(0, 12)}</code></header>
      {a.plan && <DiffView diff={a.plan.diff} />}
      {a.plan?.terraform && <details><summary>Plan Terraform</summary><pre>{a.plan.terraform}</pre></details>}
      <div className="actions"><button disabled={busy === a.id} onClick={() => decide(a.id, 'approved')}>Aprobar</button><button className="danger" disabled={busy === a.id} onClick={() => decide(a.id, 'rejected')}>Rechazar</button></div>
    </section>)}
    <h3>Historial</h3>
    <ul>{list.filter((a) => a.status !== 'pending').map((a) => <li key={a.id}>{a.status} — {a.plan?.kind} {a.plan?.targetRef} por {a.decidedBy}</li>)}</ul>
  </>;
}

function Forensics({ api }: { api: Api }) {
  const [id, setId] = useState(''); const [data, setData] = useState<any>(); const [err, setErr] = useState('');
  const go = async () => { setErr(''); setData(undefined); try { setData(await api.call('GET', `/executions/${encodeURIComponent(id)}/forensics`)); } catch (e) { setErr((e as Error).message); } };
  return <>
    <div className="row"><input placeholder="execution id (exe_…)" value={id} onChange={(e) => setId(e.target.value)} /><button onClick={go} disabled={!id}>Cargar evidencia</button></div>
    {err && <p className="err">{err}</p>}
    {data && <><p>Integridad: <b>{data.snapshot.integrity}</b> · sha256 <code>{data.snapshot.sha256.slice(0, 16)}…</code> · capturado {data.snapshot.capturedAt}</p>
      <h4>Resumen (cada línea cita su evidencia)</h4><pre>{data.incident.summary}</pre>
      <h4>Evidencia cruda (secretos redactados)</h4><pre>{JSON.stringify(data.evidence, null, 2)}</pre></>}
  </>;
}

function Iam({ api }: { api: Api }) {
  const [txt, setTxt] = useState(JSON.stringify({ roleName: 'billing-role', critical: true, grantedActions: ['s3:GetObject', 's3:PutObject', 'iam:*'], auditEvents: ['s3:GetObject'], resources: ['arn:aws:s3:::billing/*'], submitForApproval: false }, null, 2));
  const [out, setOut] = useState<any>(); const [err, setErr] = useState('');
  const run = async (submit: boolean) => { setErr(''); try { setOut(await api.call('POST', '/iam/audit-roles', { ...JSON.parse(txt), submitForApproval: submit })); } catch (e) { setErr((e as Error).message); } };
  return <>
    <p className="muted">Pega los permisos concedidos y los eventos observados en los logs de auditoría cloud.</p>
    <textarea rows={12} value={txt} onChange={(e) => setTxt(e.target.value)} spellCheck={false} />
    <div className="actions"><button onClick={() => run(false)}>Analizar (dry-run)</button><button onClick={() => run(true)}>Enviar a bandeja SecOps</button></div>
    {err && <p className="err">{err}</p>}
    {out && <><p>Uso: {(out.audit.usageRatio * 100).toFixed(0)}% — sin usar: <code>{out.audit.unused.join(', ') || 'ninguno'}</code></p>{out.plan && <DiffView diff={out.plan.diff} />}<pre>{JSON.stringify(out.audit.proposedPolicy, null, 2)}</pre></>}
  </>;
}

function App() {
  const [key, setKey] = useState(() => sessionStorage.getItem('sm_key') ?? '');
  const [tab, setTab] = useState<Tab>('exposure');
  const api = useMemo(() => new Api(key), [key]);
  if (!key) return <form className="login" onSubmit={(e) => { e.preventDefault(); const v = new FormData(e.currentTarget).get('k') as string; sessionStorage.setItem('sm_key', v); setKey(v); }}>
    <h1>SentinelMesh</h1><input name="k" type="password" placeholder="API key" autoFocus /><button>Entrar</button></form>;
  const tabs: Array<[Tab, string]> = [['exposure', 'Exposición'], ['approvals', 'Bandeja SecOps'], ['forensics', 'Forense'], ['iam', 'IAM / Políticas']];
  return <main>
    <nav><h1>SentinelMesh</h1>{tabs.map(([t, l]) => <button key={t} className={t === tab ? 'on' : ''} onClick={() => setTab(t)}>{l}</button>)}<button className="link" onClick={() => { sessionStorage.removeItem('sm_key'); setKey(''); }}>Salir</button></nav>
    {tab === 'exposure' && <Exposure api={api} />}{tab === 'approvals' && <Approvals api={api} />}{tab === 'forensics' && <Forensics api={api} />}{tab === 'iam' && <Iam api={api} />}
  </main>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
