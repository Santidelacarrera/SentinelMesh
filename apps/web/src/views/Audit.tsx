import { useState } from 'react';
import { useResource } from '../api';
import { Empty, ErrorBanner, Hash, Page, Skeleton } from '../ui/kit';
import { clock } from '../lib/format';
import type { AuditEntry } from '../types';

export function Audit() {
  const res = useResource<{ verify: { ok: boolean; brokenAt?: number }; entries: AuditEntry[] }>('/audit', 10000), [q, setQ] = useState(''), [open, setOpen] = useState<string>();
  const entries = [...(res.data?.entries ?? [])].reverse().filter((e) => !q || `${e.event} ${e.actor}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <Page title="Auditoría" lede="Registro inmutable: cada entrada incluye el hash de la anterior, así que cualquier alteración rompe la cadena."
      actions={res.data && <span className={`chip ${res.data.verify.ok ? 'ok' : 'risk'}`} role="status">{res.data.verify.ok ? `Cadena íntegra · ${res.data.entries.length} entradas` : `Cadena rota en la entrada ${res.data.verify.brokenAt}`}</span>}>
      {res.error && <ErrorBanner message={res.error} retry={res.reload} />}
      <input type="search" aria-label="Filtrar" placeholder="Filtrar por evento o persona" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 320, marginBottom: 14 }} />
      <section className="panel">{!res.data ? <Skeleton rows={6} /> : entries.length === 0 ? <Empty title="Sin entradas" /> : entries.map((e) => (
        <div key={e.id}><button className="audit-line" style={{ width: '100%', textAlign: 'left', background: 'none', border: 0, borderBottom: '1px solid var(--line-soft)', cursor: 'pointer' }} onClick={() => setOpen(open === e.id ? undefined : e.id)} aria-expanded={open === e.id}>
          <span className="muted">#{e.seq}</span><span className="muted">{clock(e.at)}</span><span><b>{e.event}</b> <span className="muted">· {e.actor}</span></span><Hash value={e.hash} n={10} /></button>
          {open === e.id && <div style={{ padding: '8px 16px 14px' }}><pre className="diff" style={{ padding: 10, margin: 0, whiteSpace: 'pre-wrap' }}>{JSON.stringify(e.data, null, 2)}</pre><p className="muted" style={{ marginTop: 6 }}>Hash anterior <Hash value={e.prevHash} n={16} /></p></div>}</div>))}</section>
    </Page>
  );
}
