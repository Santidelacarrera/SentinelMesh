import { describe, expect, it } from 'vitest';
import { buildLedger } from './ledger';
import { diffStats, parseDiff } from './diff';
import { describeImpact } from './impact';
import { ago } from './format';
import type { Plan } from '../types';

describe('ledger', () => {
  it('splits the rationale into base, signed adjustments and notes', () => {
    const l = buildLedger({ baseSeverity: 'high', exposureScore: 95, rationale: ['asset is internet-facing (+15)', 'asset handles critical data (+10)', 'something else'] });
    expect(l.base).toBe(70); expect(l.rows).toEqual([{ label: 'El activo está expuesto a Internet', delta: 15 }, { label: 'Maneja datos críticos', delta: 10 }]);
    expect(l.rows.reduce((n, r) => n + r.delta, l.base)).toBe(l.total); expect(l.notes).toEqual(['something else']);
  });
});
describe('diff', () => {
  it('classifies lines and counts changes', () => {
    const d = parseDiff('--- a\n+++ b\n  keep\n- gone\n+ new');
    expect(d.map((x) => x.kind)).toEqual(['meta', 'meta', 'ctx', 'del', 'add']); expect(diffStats(d)).toEqual({ added: 1, removed: 1 });
  });
});
describe('impact', () => {
  const base = { id: 'p', action: 'x', diff: '', planHash: 'h', applied: false, destructive: true, createdAt: '' };
  it('derives consequences from real plan params', () => {
    const iam = describeImpact({ ...base, kind: 'iam', targetRef: 'role', params: { critical: true, current: { statements: [{ actions: ['a', 'b', 'c'] }] }, proposed: { statements: [{ actions: ['a'] }] } } } as Plan);
    expect(iam.headline).toContain('1 de 3'); expect(iam.effects[0]).toContain('b, c');
    expect(describeImpact({ ...base, kind: 'rotation', targetRef: 'c', params: {} } as Plan).reversible).toBe(false);
    expect(describeImpact({ ...base, kind: 'waf', targetRef: 'gw', params: { rule: { name: 'r', action: 'block', addresses: ['1.1.1.1/32'] } } } as Plan).headline).toBe('Bloquear 1 dirección en «r»');
  });
});
describe('ago', () => { it('is relative and Spanish', () => { expect(ago(new Date(Date.now() - 5 * 60_000).toISOString())).toMatch(/hace 5 minutos/); }); });
