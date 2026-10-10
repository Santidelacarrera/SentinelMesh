import { go, useResource, useSession } from '../api';
import { Empty, ErrorBanner, Page, Sev, Skeleton } from '../ui/kit';
import { Mesh, AssetCounts } from '../ui/Mesh';
import { ago, plural } from '../lib/format';
import { KIND_LABEL } from '../lib/impact';
import type { Approval, Asset, Finding, Summary } from '../types';

export function Overview() {
  const sum = useResource<Summary>('/exposures/summary', 8000), assets = useResource<Asset[]>('/assets'), fnd = useResource<{ items: Finding[] }>('/findings?status=open&limit=500', 8000);
  const apr = useResource<Approval[]>('/approvals?status=pending', 5000);
  const { me } = useSession();
  const err = sum.error ?? assets.error ?? fnd.error ?? apr.error;
  const counts: AssetCounts = {};
  for (const f of fnd.data?.items ?? []) if (f.assetName) { const c = (counts[f.assetName] ??= {}); c[f.severity] = (c[f.severity] ?? 0) + 1; }
  const crit = sum.data?.bySeverity.critical ?? 0, pending = apr.data?.length ?? 0;
  return (
    <Page title="Resumen" lede={`Sesión de ${me.email || me.userId}. Los datos se actualizan solos.`}>
      {err && <ErrorBanner message={err} retry={() => { sum.reload(); assets.reload(); fnd.reload(); apr.reload(); }} />}
      {!sum.data || !apr.data ? <Skeleton rows={3} /> : (
        <p className="lede">
          {sum.data.totals.open === 0 ? 'No hay hallazgos abiertos. ' : <>Hay <b>{plural(sum.data.totals.open, 'hallazgo abierto', 'hallazgos abiertos')}</b>{crit ? <>, <b>{crit}</b> {crit === 1 ? 'crítico' : 'críticos'}</> : ''}
          {sum.data.totals.secrets ? <>, y <a href="#/credenciales">{plural(sum.data.totals.secrets, 'credencial expuesta', 'credenciales expuestas')}</a></> : ''}. </>}
          {pending ? <><a href="#/decisiones">{plural(pending, 'cambio espera', 'cambios esperan')} tu firma</a>; hasta entonces no se toca nada.</> : 'Ninguna acción espera una decisión.'}
        </p>
      )}
      <div className="overview" style={{ marginTop: 28 }}>
        <section className="panel queue" aria-labelledby="q-h">
          <header><h2 id="q-h">Esperan una firma</h2>{pending > 0 && <a className="chip sign" href="#/decisiones">{pending}</a>}</header>
          {!apr.data ? <Skeleton /> : pending === 0 ? <Empty title="Nada pendiente">Las remediaciones propuestas aparecerán aquí antes de ejecutarse.</Empty> : (
            <ul className="list">{apr.data.map((a) => (
              <li key={a.id}><a className="row gate" href={`#/decisiones/${a.id}`}>
                <span className="t"><span>{a.plan ? KIND_LABEL[a.plan.kind] : 'Cambio'}</span><span className="muted">{a.plan?.targetRef}</span></span>
                <span className="m"><span>solicitado {ago(a.requestedAt)}</span>{a.finding && <Sev level={a.finding.severity} />}{a.execution?.incidentId && <span className="chip risk">incidente</span>}</span>
              </a></li>))}
            </ul>)}
        </section>
        <section className="panel" aria-labelledby="m-h">
          <header><h2 id="m-h">Dónde está la exposición</h2><span className="muted">Pulsa un activo para ver sus hallazgos</span></header>
          <div className="body">{!assets.data ? <Skeleton rows={5} /> : assets.data.length === 0
            ? <Empty title="Aún no hay activos">Registra el contexto de tus servicios con POST /api/v1/assets y las severidades se ajustarán a su exposición real.</Empty>
            : <Mesh assets={assets.data} counts={counts} onPick={(n) => go(`/hallazgos?asset=${encodeURIComponent(n)}`)} />}</div>
        </section>
      </div>
    </Page>
  );
}
