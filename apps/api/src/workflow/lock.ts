import { randomUUID } from 'node:crypto';
import type Redis from 'ioredis';

export class LockBusyError extends Error {}
export interface ExecutionLock { acquire(key: string, ttlMs: number): Promise<() => Promise<void>> }
export const EXECUTION_LOCK = Symbol('EXECUTION_LOCK');

export class MemoryLock implements ExecutionLock {
  private held = new Set<string>();
  async acquire(key: string) {
    if (this.held.has(key)) throw new LockBusyError(`execution ${key} is being advanced by another worker`);
    this.held.add(key);
    return async () => { this.held.delete(key); };
  }
}

/** Redis mutex (SET NX PX + owner token, compare-and-delete release). The TTL bounds the damage of a crashed holder. */
export class RedisLock implements ExecutionLock {
  constructor(private redis: Redis) {}
  async acquire(key: string, ttlMs: number) {
    const token = randomUUID(); const k = `sm:lock:${key}`;
    if ((await this.redis.set(k, token, 'PX', ttlMs, 'NX')) !== 'OK') throw new LockBusyError(`execution ${key} is being advanced by another worker`);
    return async () => {
      await this.redis.eval(`if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`, 1, k, token);
    };
  }
}
