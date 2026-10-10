import { BullQueue } from '../src/queue/queue';

const url = process.env.REDIS_URL;
(url ? describe : describe.skip)('BullMQ adapter (needs REDIS_URL)', () => {
  it('delivers jobs and retries failures with backoff', async () => {
    const q = new BullQueue(url!, `t-${Date.now()}`);
    let calls = 0; const done = new Promise<void>((res) => {
      q.process(async () => { if (++calls < 2) throw new Error('boom'); res(); });
    });
    await q.enqueue({ orgId: 'o', executionId: 'e' });
    await done;
    expect(calls).toBe(2);
    await q.close();
  }, 20000);
});
