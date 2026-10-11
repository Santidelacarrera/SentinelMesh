import { CircuitBreaker } from '../src/common/breaker';
import { AnalyticsClient } from '../src/analytics/analytics.client';

describe('circuit breaker', () => {
  it('opens after N failures, lets exactly one probe through after the cool-down, and closes on success', () => {
    let t = 0; const b = new CircuitBreaker({ threshold: 3, coolDownMs: 1000, now: () => t });
    for (let i = 0; i < 3; i++) { expect(b.allow()).toBe(true); b.failure(); }
    expect(b.state).toBe('open'); expect(b.allow()).toBe(false);
    t = 999; expect(b.allow()).toBe(false);
    t = 1000; expect(b.state).toBe('half-open');
    expect(b.allow()).toBe(true); expect(b.allow()).toBe(false);          // single probe
    b.failure(); expect(b.state).toBe('open'); t = 2000; expect(b.state).toBe('half-open');
    expect(b.allow()).toBe(true); b.success(); expect(b.state).toBe('closed'); expect(b.allow()).toBe(true);
  });
  it('success resets the failure streak', () => {
    const b = new CircuitBreaker({ threshold: 3, coolDownMs: 1000 });
    b.failure(); b.failure(); b.success(); b.failure(); b.failure(); expect(b.state).toBe('closed');
  });

  it('analytics client: a dead service costs three timeouts, then calls short-circuit to the local fallback', async () => {
    let calls = 0;
    const dead = (async () => { calls++; throw new Error('connect ECONNREFUSED'); }) as unknown as typeof fetch;
    const c = new AnalyticsClient('http://analytics:8000', dead, 50);
    const input = { ruleId: 'r', kind: 'vulnerability' as const, severity: 'high' as const };
    for (let i = 0; i < 10; i++) expect((await c.correlate(input)).severity).toBeDefined();   // always answers (fail-safe local scoring)
    expect(calls).toBe(3);
    expect(c.breaker.state).toBe('open');
  });
});
