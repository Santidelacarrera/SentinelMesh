export interface Plan { id: string; kind: string; targetRef: string; diff: string; terraform?: string; planHash: string; applied: boolean }
export interface Approval { id: string; executionId: string; stepName: string; status: 'pending' | 'approved' | 'rejected'; planHash: string; plan?: Plan; decidedBy?: string; requestedAt: string }
export interface Summary { totals: { open: number; suppressed: number; secrets: number }; bySeverity: Record<string, number>; byAsset: Record<string, number>; top: Array<{ id: string; title: string; severity: string; baseSeverity: string; exposureScore: number; asset?: string; kind: string }> }

export class Api {
  constructor(public key: string) {}
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const r = await fetch(`/api/v1${path}`, { method, headers: { 'x-api-key': this.key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((j as any).message ?? `HTTP ${r.status}`);
    return j as T;
  }
}
