import { AnalyticsClient, localCorrelate, localLeastPrivilege, localSummary } from '../src/analytics/analytics.client';

// Contract test: the in-process fallback and the Python service must give identical answers (needs ANALYTICS_TEST_URL, e.g. http://127.0.0.1:8099).
const url = process.env.ANALYTICS_TEST_URL;
(url ? describe : describe.skip)('analytics service ⇄ local fallback parity (needs ANALYTICS_TEST_URL)', () => {
  const remote = () => new AnalyticsClient(url);
  const asset = (o: object) => ({ internetFacing: false, behindGateway: false, handlesCriticalData: false, environment: 'prod' as const, ...o });
  const cases = [
    { ruleId: 'r', kind: 'vulnerability' as const, severity: 'high' as const, asset: asset({ internetFacing: true, handlesCriticalData: true }) },
    { ruleId: 'r', kind: 'vulnerability' as const, severity: 'medium' as const, asset: asset({ behindGateway: true, environment: 'dev' as const }) },
    { ruleId: 'r', kind: 'secret' as const, severity: 'critical' as const, asset: asset({ behindGateway: true, environment: 'dev' as const }) },
    { ruleId: 'r', kind: 'vulnerability' as const, severity: 'low' as const },
    { ruleId: 'r', kind: 'secret' as const, severity: 'high' as const, likelyFalsePositive: true },
    { ruleId: 'r', kind: 'vulnerability' as const, severity: 'critical' as const, asset: asset({ internetFacing: true, behindGateway: true, handlesCriticalData: true }) },
  ];
  it.each(cases.map((c, i) => [i, c] as const))('correlate case %i', async (_i, c) => { expect(await remote().correlate(c)).toEqual(localCorrelate(c)); });
  it('least privilege (wildcards, unknown events)', async () => {
    const granted = ['s3:*', 'iam:PassRole', 'ec2:Describe*'], used = ['s3:GetObject', 'ec2:DescribeInstances', 'x:Y'];
    expect(await remote().leastPrivilege(granted, used, ['*'])).toEqual(localLeastPrivilege(granted, used, ['*']));
  });
  it('grounded summary cites every evidence item', async () => {
    const ev = [{ id: 'ev-1', type: 'log', text: '401 /login' }, { id: 'ev-2', type: 'metrics', text: '{"rps":900}' }];
    expect(await remote().summarize(ev)).toEqual(localSummary(ev));
    expect(await remote().summarize([])).toEqual(localSummary([]));
  });
});
