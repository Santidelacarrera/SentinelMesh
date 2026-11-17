import { Injectable, Logger } from '@nestjs/common';

/** Tiny in-process pub/sub so CTEM, IAM, signals and findings can raise events without importing the SOAR engine (no circular modules). */
export type DomainEvent = { actor?: string } & (
  | { type: 'signal'; orgId: string; entity: Record<string, any> }
  | { type: 'finding'; orgId: string; entity: Record<string, any> }
  | { type: 'vulnerability'; orgId: string; entity: Record<string, any> }
  | { type: 'exposure'; orgId: string; entity: Record<string, any> }
  | { type: 'identity'; orgId: string; entity: Record<string, any> });

@Injectable()
export class EventBus {
  private log = new Logger('EventBus');
  private subs: Array<(e: DomainEvent) => Promise<void>> = [];
  subscribe(fn: (e: DomainEvent) => Promise<void>) { this.subs.push(fn); }
  /** Handlers never break the publisher: a failing playbook must not fail an ingest. */
  async emit(e: DomainEvent) { for (const s of this.subs) await s(e).catch((err) => this.log.error(`handler for ${e.type} failed: ${(err as Error).message}`)); }
}
