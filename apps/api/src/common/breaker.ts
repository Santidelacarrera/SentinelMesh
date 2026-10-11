/**
 * Client-side circuit breaker (complements the mesh's outlier detection): when a dependency keeps failing, stop paying its
 * timeout on every call and go straight to the fallback; probe again after a cool-down.
 * closed → (N consecutive failures) → open → (cool-down) → half-open → (probe ok) → closed, (probe fails) → open.
 */
export class CircuitBreaker {
  private failures = 0; private openedAt = 0; private probing = false;
  constructor(private o: { threshold: number; coolDownMs: number; now?: () => number }) {}
  private now() { return (this.o.now ?? Date.now)(); }
  get state(): 'closed' | 'open' | 'half-open' {
    if (this.failures < this.o.threshold) return 'closed';
    return this.now() - this.openedAt >= this.o.coolDownMs ? 'half-open' : 'open';
  }
  /** Returns false when the call must be skipped. In half-open exactly one caller gets to probe. */
  allow(): boolean {
    const s = this.state;
    if (s === 'closed') return true;
    if (s === 'open') return false;
    if (this.probing) return false;
    this.probing = true; return true;
  }
  success() { this.failures = 0; this.probing = false; }
  failure() { this.failures++; this.probing = false; if (this.failures >= this.o.threshold) this.openedAt = this.now(); }
}
