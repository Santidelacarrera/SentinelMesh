import { ReactNode, useEffect, useRef, useState } from 'react';
import type { Severity } from '../types';
import { SEV_LABEL } from '../lib/format';

/** Shape + word + colour: severity is readable without colour. */
export function Sev({ level, short }: { level: Severity; short?: boolean }) {
  const shape = { critical: <path d="M7 1l6 6-6 6-6-6z" />, high: <path d="M7 1.5l6 10.5H1z" />, medium: <circle cx="7" cy="7" r="5.5" />, low: <circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" strokeWidth="2" />, info: <rect x="3" y="6" width="8" height="2" rx="1" /> }[level];
  return <span className={`sev sev-${level}`}><svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor" aria-hidden>{shape}</svg>{short ? <span className="sr">{SEV_LABEL[level]}</span> : SEV_LABEL[level]}</span>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) { return <div className="empty"><strong>{title}</strong>{children && <p>{children}</p>}</div>; }
export function Skeleton({ rows = 4 }: { rows?: number }) { return <div className="body" aria-busy="true" aria-label="Cargando" style={{ display: 'grid', gap: 12 }}>{Array.from({ length: rows }, (_, i) => <div key={i} className="skel" style={{ width: `${90 - i * 12}%` }} />)}</div>; }
export function ErrorBanner({ message, retry }: { message: string; retry?: () => void }) { return <div className="err-banner" role="alert"><span>{message}</span>{retry && <button className="btn" onClick={retry}>Reintentar</button>}</div>; }
export function Hash({ value, n = 12 }: { value: string; n?: number }) { return <code title={value}>{value.slice(0, n)}</code>; }

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: Array<[T, string]>; value: T; onChange: (t: T) => void }) {
  return <div className="tabs" role="tablist">{tabs.map(([k, l]) => <button key={k} role="tab" aria-selected={value === k} onClick={() => onChange(k)}>{l}</button>)}</div>;
}

export function Page({ title, lede, actions, children }: { title: string; lede?: string; actions?: ReactNode; children: ReactNode }) {
  return <><div className="page-head"><div><h1>{title}</h1>{lede && <p>{lede}</p>}</div>{actions}</div>{children}</>;
}

/**
 * Signing is deliberate: press and hold (pointer, or Space/Enter) until the bar fills. Releasing early cancels, so a stray click
 * can never authorise a destructive change. `onConfirm` fires once per completed hold.
 */
export function HoldToSign({ label, holdingLabel = 'Sigue pulsando…', ms = 1200, disabled, onConfirm }: { label: string; holdingLabel?: string; ms?: number; disabled?: boolean; onConfirm: () => void }) {
  const [p, setP] = useState(0);
  const raf = useRef(0), t0 = useRef(0), done = useRef(false);
  const stop = () => { cancelAnimationFrame(raf.current); started.current = false; t0.current = 0; setP(0); };
  const started = useRef(false);
  // Progress is driven by the timestamp rAF hands to the callback (no clock reads while rendering).
  const tick = (ts: number) => {
    if (!started.current) return;
    if (!t0.current) t0.current = ts || 1;
    const f = Math.min(1, (ts - t0.current) / ms);
    setP(f);
    if (f >= 1) { started.current = false; if (!done.current) { done.current = true; onConfirm(); } t0.current = 0; return; }
    raf.current = requestAnimationFrame(tick);
  };
  const start = () => { if (disabled || started.current) return; done.current = false; started.current = true; t0.current = 0; raf.current = requestAnimationFrame(tick); };
  useEffect(() => () => cancelAnimationFrame(raf.current), []);
  return (
    <button type="button" className="hold" disabled={disabled} aria-describedby="hold-help"
      onPointerDown={(e) => { e.currentTarget.setPointerCapture?.(e.pointerId); start(); }} onPointerUp={stop} onPointerCancel={stop} onPointerLeave={stop}
      onKeyDown={(e) => { if ((e.key === ' ' || e.key === 'Enter') && !e.repeat) { e.preventDefault(); start(); } }} onKeyUp={(e) => { if (e.key === ' ' || e.key === 'Enter') stop(); }} onBlur={stop}>
      <i className="fill" style={{ transform: `scaleX(${p})` }} />
      <span>{p > 0 && p < 1 ? holdingLabel : label}</span>
      <span id="hold-help" className="sr">Mantén pulsado el botón hasta que se complete la barra. Si lo sueltas antes, no se firma nada.</span>
    </button>
  );
}
