import type { Asset, Severity } from '../types';
import { SEV_LABEL, SEV_ORDER } from '../lib/format';

export type AssetCounts = Record<string, Partial<Record<Severity, number>>>;
const COLOR: Record<Severity, string> = { critical: 'var(--risk)', high: '#d9531e', medium: '#c98a12', low: 'var(--steel)', info: 'var(--line)' };

/** Where each asset sits explains its score: reachable from the Internet? shielded by the gateway? Nodes are donuts of open findings by severity. */
export function Mesh({ assets, counts, onPick }: { assets: Asset[]; counts: AssetCounts; onPick: (name: string) => void }) {
  const W = 600, H = 380, padX = 56, padY = 38, qw = (W - padX) / 2, qh = (H - padY) / 2;
  const quad = (a: Asset) => ({ row: a.internetFacing ? 0 : 1, col: a.behindGateway ? 1 : 0 });
  const groups = new Map<string, Asset[]>();
  for (const a of assets) { const q = quad(a); const k = `${q.row}${q.col}`; groups.set(k, [...(groups.get(k) ?? []), a]); }
  const zones = [{ row: 0, col: 0, label: 'Expuesto sin protección', danger: true }, { row: 0, col: 1, label: 'Expuesto tras el gateway' }, { row: 1, col: 0, label: 'Interno sin gateway' }, { row: 1, col: 1, label: 'Interno tras el gateway' }];
  return (
    <figure style={{ margin: 0 }}>
      <svg className="mesh" viewBox={`0 0 ${W} ${H}`} role="group" aria-label="Mapa de exposición de activos">
        {zones.map((z) => {
          const x = padX + z.col * qw, y = padY + z.row * qh;
          return <g key={z.label}>
            <rect x={x + 3} y={y + 3} width={qw - 6} height={qh - 6} rx="10" fill={z.danger ? 'var(--risk-bg)' : 'var(--surface)'} stroke="var(--line)" strokeDasharray={z.danger ? '0' : '4 4'} />
            <text x={x + 14} y={y + 22} className="zone-label">{z.label}</text>
          </g>;
        })}
        <text x={padX / 2} y={padY + qh / 2} className="zone-label" textAnchor="middle" transform={`rotate(-90 ${padX / 2} ${padY + qh / 2})`}>Internet</text>
        <text x={padX / 2} y={padY + qh * 1.5} className="zone-label" textAnchor="middle" transform={`rotate(-90 ${padX / 2} ${padY + qh * 1.5})`}>Red interna</text>
        {[...groups.entries()].flatMap(([k, list]) => {
          const row = Number(k[0]), col = Number(k[1]);
          return list.map((a, i) => {
            const c = counts[a.name] ?? {}, n = SEV_ORDER.reduce((s, v) => s + (c[v] ?? 0), 0);
            const r = 20 + Math.min(14, Math.sqrt(n) * 5), cx = padX + col * qw + (qw / (list.length + 1)) * (i + 1), cy = padY + row * qh + qh / 2 + 6;
            const C = 2 * Math.PI * r; let off = 0;
            return (
              <g key={a.id} className="node" tabIndex={0} role="button" aria-label={`${a.name}: ${n} hallazgos abiertos${a.handlesCriticalData ? ', datos críticos' : ''}`} onClick={() => onPick(a.name)} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onPick(a.name)}>
                <circle className="halo" cx={cx} cy={cy} r={r + 9} />
                <circle cx={cx} cy={cy} r={r} fill="var(--raised)" stroke="var(--line)" strokeWidth="7" />
                {SEV_ORDER.map((s) => { const len = ((c[s] ?? 0) / Math.max(n, 1)) * C; const el = len ? <circle key={s} cx={cx} cy={cy} r={r} fill="none" stroke={COLOR[s]} strokeWidth="7" strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-off} transform={`rotate(-90 ${cx} ${cy})`} /> : null; off += len; return el; })}
                <text x={cx} y={cy + 5} textAnchor="middle" fontWeight="700" fontSize="15">{n}</text>
                {a.handlesCriticalData && <rect x={cx + r - 6} y={cy - r - 4} width="11" height="11" rx="2" fill="var(--ink)" stroke="var(--raised)" strokeWidth="2"><title>Maneja datos críticos</title></rect>}
                <text x={cx} y={cy + r + 18} textAnchor="middle" fontSize="12.5" fontWeight="550">{a.name}</text>
              </g>
            );
          });
        })}
      </svg>
      <figcaption className="legend">
        {SEV_ORDER.slice(0, 4).map((s) => <span key={s}><svg width="10" height="10" aria-hidden><circle cx="5" cy="5" r="5" fill={COLOR[s]} /></svg> {SEV_LABEL[s]}</span>)}
        <span><svg width="10" height="10" aria-hidden><rect width="10" height="10" rx="2" fill="var(--ink)" /></svg> Datos críticos</span>
      </figcaption>
    </figure>
  );
}
