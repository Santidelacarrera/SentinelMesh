import type { Finding, Severity } from '../types';

const BASE: Record<Severity, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 5 };
export interface LedgerRow { label: string; delta: number }
export interface Ledger { base: number; rows: LedgerRow[]; total: number; notes: string[] }

/** Turns the correlation rationale ("asset is internet-facing (+15)") into an auditable base → adjustments → score ledger. */
export function buildLedger(f: Pick<Finding, 'baseSeverity' | 'rationale' | 'exposureScore'>): Ledger {
  const rows: LedgerRow[] = [], notes: string[] = [];
  for (const r of f.rationale) {
    const m = /^(.*?)\s*\(([+-]\d+)\)$/.exec(r);
    if (m) rows.push({ label: translate(m[1]), delta: Number(m[2]) }); else notes.push(translate(r));
  }
  const base = BASE[f.baseSeverity];
  return { base, rows, total: f.exposureScore, notes };
}

const ES: Array<[RegExp, string]> = [
  [/^asset is internet-facing$/, 'El activo está expuesto a Internet'], [/^asset not internet-facing$/, 'El activo no está expuesto a Internet'],
  [/^protected by API gateway$/, 'Protegido por el API Gateway'], [/^asset handles critical data$/, 'Maneja datos críticos'], [/^dev environment$/, 'Entorno de desarrollo'],
  [/^no asset context: severity kept as reported \(conservative\)$/, 'Sin contexto del activo: se mantiene la severidad del escáner'],
  [/^matched false-positive heuristics$/, 'Coincide con patrones de falso positivo (pruebas, ejemplos, marcadores)'],
];
export function translate(s: string): string { for (const [re, t] of ES) if (re.test(s)) return t; return s; }
