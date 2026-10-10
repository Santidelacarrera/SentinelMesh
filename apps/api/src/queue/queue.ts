import { Logger } from '@nestjs/common';

export interface Job { orgId: string; executionId: string }
export type JobHandler = (job: Job) => Promise<void>;

export interface JobQueue {
  enqueue(job: Job): Promise<void>;
  process(handler: JobHandler): void;
  close(): Promise<void>;
}
export const JOB_QUEUE = Symbol('JOB_QUEUE');

/** Same retry/backoff semantics as the BullMQ adapter, in-process (tests, local dev without Redis). */
export class MemoryQueue implements JobQueue {
  private handler?: JobHandler;
  private inflight = new Set<Promise<void>>();
  private log = new Logger('MemoryQueue');
  constructor(private attempts = 3, private backoffMs = 0) {}
  process(h: JobHandler) { this.handler = h; }
  async enqueue(job: Job) { this.run(job, 1); }
  private run(job: Job, attempt: number) {
    const p = (async () => {
      try { await this.handler?.(job); }
      catch (e) {
        if (attempt < this.attempts) {
          this.log.warn(`job ${job.executionId} attempt ${attempt} failed: ${(e as Error).message}`);
          await new Promise((r) => setTimeout(r, this.backoffMs * 2 ** (attempt - 1)));
          this.run(job, attempt + 1);
        }
      }
    })().finally(() => this.inflight.delete(p));
    this.inflight.add(p);
  }
  /** Test helper: wait until all queued work (including retries) settles. */
  async idle() { while (this.inflight.size) await Promise.all([...this.inflight]); }
  async close() { await this.idle(); }
}

export class BullQueue implements JobQueue {
  private queue: import('bullmq').Queue;
  private worker?: import('bullmq').Worker;
  constructor(private redisUrl: string, private name = 'sentinelmesh-workflows') {
    const { Queue } = require('bullmq') as typeof import('bullmq');
    this.queue = new Queue(name, { connection: BullQueue.conn(redisUrl) });
  }
  static conn(url: string) {
    const u = new URL(url);
    return { host: u.hostname, port: Number(u.port || 6379), password: u.password || undefined, maxRetriesPerRequest: null as null };
  }
  async enqueue(job: Job) {
    // jobId = executionId + attempt epoch avoids duplicate concurrent runs of the same execution
    await this.queue.add('advance', job, { attempts: 5, backoff: { type: 'exponential', delay: 1000 }, removeOnComplete: 1000, removeOnFail: false });
  }
  process(handler: JobHandler) {
    const { Worker } = require('bullmq') as typeof import('bullmq');
    this.worker = new Worker(this.name, async (j) => handler(j.data as Job), { connection: BullQueue.conn(this.redisUrl), concurrency: 4 });
  }
  async close() { await this.worker?.close(); await this.queue.close(); }
}
