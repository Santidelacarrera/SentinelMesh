import { FormEvent, useState } from 'react';
import { go, useResource, useSession, useToast, refreshAll } from '../api';
import { Empty, ErrorBanner, Hash, Page, Sev, Skeleton } from '../ui/kit';
import { SEV_LABEL, SEV_ORDER, ago } from '../lib/format';
import { buildLedger } from '../lib/ledger';
import { DiffView } from './Decisions';
import type { Finding, Plan, Severity, Trace } from '../types';

export function Findings({ id, query }: { id?: string; query: URLSearchParams }) {
  const asset = query.get('asset') ?? '', selected = id ?? query.get('id') ?? undefined;
  const [sev, setSev] = useState<Severity[]>([]), [kind, setKind] = useState(''), [status, setStatus] = useState('open,remediating'), [q, setQ] = useState('');
  const p = new URLSearchParams(); if (sev.length) p.set('severity', sev.join(',')); if (kind) p.set('kind', kind); if (status) p.set('status', status); if (q) p.set('q', q); if (asset) p.set('asset', asset); p.set('limit', '200');
  const res = useResource<{ total: number; items: Finding[] }>(`/findings?${p}`, 10000);
  const toggle = (s: Severity) => setSev((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const items = res.data?.items ?? [], current = items.find((f) => f.id === selected);
  const open = (fid: string) => go(`/hallazgos/${fid}${asset ? `?asset=${encodeURIComponent(asset)}` : ''}`);
  return (
    <Page title="Hallazgos" lede="Ordenados por exposición real, no por la severidad que declara el escáner.">
      <div className="filters" role="group" aria-label="Filtros">
        {SEV_ORDER.slice(0, 4).map((s) => <button key={s} className="toggle" aria-pressed={sev.includes(s)} onClick={() => toggle(s)}>{SEV_LABEL[s]}</button>)}
        <select aria-label="Tipo" value={kind} onChange={(e) => setKind(e.target.value)} style={{ width: 'auto' }}><option value="">Todos los tipos</option><option value="vulnerability">Vulnerabilidades</option><option value="secret">Secretos</option></select>
        <select aria-label="Estado" value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 'auto' }}><option value="open,remediating">Abiertos y en remediación</option><option value="open">Solo sin tratar</option><option value="remediating">En remediación</option><option value="suppressed">Suprimidos (falsos positivos)</option><option value="">Todos</option></select>
        <input type="search" aria-label="Buscar" placeholder="Buscar por título, regla o ruta" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 280 }} />
        {asset && <button className="chip sign" onClick={() => go('/hallazgos')}>Activo: {asset} ✕</button>}
      </div>
      {res.error && <ErrorBanner message={res.error} retry={res.reload} />}
      <div className="split findings">
        <section className="panel" aria-label="Lista de hallazgos">
          {!res.data ? <Skeleton rows={6} /> : items.length === 0 ? <Empty title="Sin resultados">Cambia los filtros o ingesta un informe con POST /api/v1/scans/ingest.</Empty> : (
            <table><thead><tr><th>Hallazgo</th><th>Severidad</th><th>Exposición</th></tr></thead><tbody>
              {items.map((f) => <tr key={f.id} className={`click ${f.id === selected ? 'sel' : ''}`} onClick={() => open(f.id)}>
                <td><a href={`#/hallazgos/${f.id}${asset ? `?asset=${encodeURIComponent(asset)}` : ''}`} onClick={(e) => e.stopPropagation()} style={{ textDecoration: 'none', fontWeight: 600 }}>{f.kind === 'secret' ? 'Clave expuesta · ' : ''}{f.title}</a>
                  <div className="muted">{f.assetName ?? 'sin activo'} · {f.location ?? f.ruleId}</div></td>
                <td><Sev level={f.severity} />{f.severity !== f.baseSeverity && <div className="muted">el escáner dijo {SEV_LABEL[f.baseSeverity].toLowerCase()}</div>}</td>
                <td className="nowrap"><b>{f.exposureScore}</b><span className="muted"> / 100</span></td></tr>)}
            </tbody></table>)}
        </section>
        {current ? <Detail key={current.id} f={current} onChanged={res.reload} /> : <section className="panel"><Empty title="Elige un hallazgo">Verás por qué tiene esa severidad y de qué informe procede.</Empty></section>}
      </div>
    </Page>
  );
}

function Detail({ f, onChanged }: { f: Finding; onChanged: () => void }) {
  const trace = useResource<Trace>(`/findings/${f.id}/trace`);
  const { me, api } = useSession(), toast = useToast(), canAct = me.role !== 'viewer';
  const ledger = buildLedger(f);
  const [form, setForm] = useState(false), [busy, setBusy] = useState(false), [err, setErr] = useState(''), [plan, setPlan] = useState<Plan>();
  const rotate = async () => { setBusy(true); setErr(''); try { await api.post('/secrets/rotate', { credentialId: f.credentialId, findingId: f.id }); toast('Rotación iniciada. La revocación esperará tu firma.'); onChanged(); refreshAll(); go('/ejecuciones'); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  const simulate = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault(); const d = new FormData(e.currentTarget); setBusy(true); setErr('');
    const addresses = String(d.get('cidrs')).split(/[\s,]+/).filter(Boolean);
    try { const r = await api.post<{ plan: Plan; executionId?: string }>('/remediations/simulate', { findingId: f.id, kind: 'waf', targetRef: String(d.get('target')), submitForApproval: d.get('submit') === 'on', params: { rule: { name: String(d.get('name')), action: 'block', priority: 10, addresses } } });
      setPlan(r.plan); toast(r.executionId ? 'Plan enviado a Decisiones.' : 'Plan simulado. No se ha aplicado nada.'); onChanged(); refreshAll(); }
    catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  return (
    <article className="panel" aria-labelledby="fd-h">
      <header><h2 id="fd-h">{f.title}</h2><Sev level={f.severity} /></header>
      <div className="body stack">
        <p className="muted">{f.description || f.ruleId}</p>
        <section aria-labelledby="why"><h3 id="why" style={{ marginBottom: 8, fontSize: 13 }} className="muted">Por qué esta severidad</h3>
          {f.status === 'suppressed' ? <p className="note">Suprimido: {f.suppressionReason}</p> : (
            <div className="ledger">
              <div className="line base"><span>Severidad del escáner: {SEV_LABEL[f.baseSeverity].toLowerCase()}</span><span className="bar"><i style={{ width: `${ledger.base}%` }} /></span><b>{ledger.base}</b></div>
              {ledger.rows.map((r) => <div key={r.label} className={`line ${r.delta > 0 ? 'up' : 'down'}`}><span>{r.label}</span><span className="bar"><i style={{ left: `${Math.min(ledger.base, ledger.base + r.delta)}%`, width: `${Math.abs(r.delta)}%` }} /></span><b>{r.delta > 0 ? '+' : '−'}{Math.abs(r.delta)}</b></div>)}
              {ledger.notes.map((n) => <p key={n} className="muted">{n}</p>)}
              <div className="line total"><span>Exposición</span><span /><b>{ledger.total}</b></div>
            </div>)}
        </section>
        <section aria-labelledby="orig"><h3 id="orig" style={{ marginBottom: 4, fontSize: 13 }} className="muted">De dónde viene</h3>
          {trace.error ? <ErrorBanner message={trace.error} retry={trace.reload} /> : !trace.data ? <Skeleton rows={2} /> : (
            <div className="chain">
              <div><span className="pin" /><span><b>Informe</b> {trace.data.scan?.source} <span className="muted">· {trace.data.scan?.format} · {ago(trace.data.scan?.createdAt ?? f.createdAt)}</span><br /><span className="muted">sha256 </span><Hash value={trace.data.scan?.reportSha256 ?? ''} n={16} /></span></div>
              <div><span className="pin" /><span><b>Hallazgo</b> {f.ruleId} <span className="muted">{f.location}</span>{f.maskedSecret && <> <code>{f.maskedSecret}</code></>}</span></div>
              <div><span className="pin" style={{ background: 'var(--sign)' }} /><span><b>Mitigación</b> {trace.data.plans.length === 0 ? <span className="muted">aún sin plan simulado</span> : trace.data.plans.map((p) => <a key={p.id} className="chip sign" href="#/decisiones" style={{ marginLeft: 6 }}>{p.kind} → {p.targetRef}</a>)}</span></div>
            </div>)}
        </section>
        {err && <p role="alert" style={{ color: 'var(--risk)' }}>{err}</p>}
        {f.status !== 'suppressed' && f.status !== 'resolved' && (f.kind === 'secret' && f.credentialId
          ? <div><button className="btn primary" disabled={!canAct || busy || f.status === 'remediating'} onClick={rotate}>{f.status === 'remediating' ? 'Rotación en curso' : 'Rotar credencial'}</button><p className="muted" style={{ marginTop: 6 }}>Crea una clave nueva, la comprueba con el servicio y solo entonces pide permiso para revocar la antigua.</p></div>
          : f.kind === 'vulnerability' && <div>{!form ? <button className="btn" disabled={!canAct} onClick={() => setForm(true)}>Simular regla de WAF…</button> : (
            <form onSubmit={simulate} className="stack" style={{ gap: 10 }}>
              <label className="field"><span>Gateway o WAF de destino</span><input type="text" name="target" required defaultValue={f.assetName ? `${f.assetName}-gateway` : ''} /></label>
              <label className="field"><span>Nombre de la regla</span><input type="text" name="name" required pattern="[\w-]+" defaultValue={`block-${f.ruleId.replace(/[^\w]+/g, '-')}`} /></label>
              <label className="field"><span>Rangos a bloquear (CIDR, separados por espacios)</span><textarea name="cidrs" required placeholder="203.0.113.0/24 198.51.100.17/32" /></label>
              <label style={{ display: 'flex', gap: 8 }}><input type="checkbox" name="submit" defaultChecked /> Enviar a Decisiones para firma</label>
              <div><button className="btn primary" disabled={busy}>Generar plan</button> <button type="button" className="btn ghost" onClick={() => setForm(false)}>Cancelar</button></div>
            </form>)}{plan && <div style={{ marginTop: 12 }}><DiffView diff={plan.diff} /></div>}
            {!canAct && <p className="muted">Con rol viewer solo puedes consultar.</p>}</div>)}
      </div>
    </article>
  );
}
