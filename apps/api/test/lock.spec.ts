import Redis from 'ioredis';
import { LockBusyError, MemoryLock, RedisLock } from '../src/workflow/lock';

const locks: Array<[string, () => { lock: any; close: () => void }]> = [['memory', () => ({ lock: new MemoryLock(), close() {} })]];
if (process.env.REDIS_URL) locks.push(['redis', () => { const r = new Redis(process.env.REDIS_URL!); return { lock: new RedisLock(r), close: () => r.disconnect() }; }]);

describe.each(locks)('execution lock (%s)', (_n, make) => {
  it('is exclusive, releasable, and expires for crashed holders', async () => {
    const { lock, close } = make(); const k = `k-${Date.now()}`;
    const rel = await lock.acquire(k, 150);
    await expect(lock.acquire(k, 150)).rejects.toBeInstanceOf(LockBusyError);
    await rel();
    const rel2 = await lock.acquire(k, 150); await rel2();
    if (_n === 'redis') { await lock.acquire(k, 100); await new Promise((r) => setTimeout(r, 150)); await (await lock.acquire(k, 100))(); }
    close();
  });
  it('a stale holder cannot release a lock it no longer owns (redis)', async () => {
    if (_n !== 'redis') return;
    const { lock, close } = make(); const k = `s-${Date.now()}`;
    const stale = await lock.acquire(k, 50); await new Promise((r) => setTimeout(r, 80));
    const fresh = await lock.acquire(k, 5000); await stale();
    await expect(lock.acquire(k, 100)).rejects.toBeInstanceOf(LockBusyError);
    await fresh(); close();
  });
});
