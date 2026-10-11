import test from 'node:test';
import assert from 'node:assert/strict';
import { build, loadCatalog, ms, merged, operator } from '../generate.mjs';

const c = loadCatalog(process.env.MESH_CATALOG);
const out = build(c);
const all = Object.values(out).flat();
const of = (kind) => all.filter((d) => d.kind === kind);
const names = Object.keys(c.services);
const svc = (n) => merged(c, c.services[n]);

test('mTLS is STRICT everywhere: mesh-wide, namespace, per workload; nothing weakens it', () => {
  const pa = of('PeerAuthentication');
  assert.ok(pa.some((d) => d.metadata.namespace === 'istio-system' && d.spec.mtls.mode === 'STRICT' && !d.spec.selector), 'mesh-wide STRICT');
  assert.ok(pa.every((d) => d.spec.mtls.mode === 'STRICT'), 'no PERMISSIVE/DISABLE anywhere');
  for (const n of names) assert.ok(pa.some((d) => d.spec.selector?.matchLabels.app === n), `${n} has its own STRICT policy`);
  for (const dr of of('DestinationRule')) assert.equal(dr.spec.trafficPolicy.tls.mode, 'ISTIO_MUTUAL', `${dr.metadata.name} originates mTLS`);
  assert.equal(operator(c).spec.meshConfig.outboundTrafficPolicy.mode, 'REGISTRY_ONLY');
});

test('authorization: default-deny plus identity-based allows that match the declared call graph exactly', () => {
  const deny = of('AuthorizationPolicy').find((d) => d.metadata.name === 'deny-all');
  assert.deepEqual(deny.spec, {}, 'empty spec denies everything in the namespace');
  const allowed = new Set();
  for (const p of of('AuthorizationPolicy').filter((d) => d.metadata.name.startsWith('allow-'))) {
    const target = p.spec.selector.matchLabels.app;
    for (const r of p.spec.rules) for (const f of r.from) for (const pr of f.source.principals) {
      assert.ok(!pr.includes('*'), 'no wildcard principals');
      assert.ok(!f.source.namespaces && !f.source.ipBlocks, 'identity (SPIFFE), never IP or whole namespace');
      allowed.add(`${pr.split('/sa/')[1]}->${target}`);
    }
  }
  const declared = new Set();
  for (const [n, s] of Object.entries(c.services)) for (const caller of s.callers) declared.add(`${caller === 'gateway' ? 'istio-ingressgateway-service-account' : caller}->${n}`);
  assert.deepEqual([...allowed].sort(), [...declared].sort());
  // egressTo and callers must describe the same edges
  for (const [n, s] of Object.entries(c.services)) for (const t of s.egressTo ?? []) assert.ok(c.services[t].callers.includes(n), `${n} calls ${t} but ${t} does not list it as a caller`);
  for (const [n, s] of Object.entries(c.services)) for (const caller of s.callers) if (caller !== 'gateway') assert.ok((c.services[caller].egressTo ?? []).includes(n), `${n} lists caller ${caller} that does not declare egressTo ${n}`);
});

test('least privilege on the sensitive edge: shadowapi-guard may only POST the incident trigger on sentinelmesh-api', () => {
  const pol = of('AuthorizationPolicy').find((d) => d.metadata.name === 'allow-sentinelmesh-api');
  const rule = pol.spec.rules.find((r) => r.from[0].source.principals[0].endsWith('/sa/shadowapi-guard'));
  assert.deepEqual(rule.to[0].operation.methods, ['POST']);
  assert.deepEqual(rule.to[0].operation.paths, ['/api/v1/incidents/trigger']);
});

test('every service gets the full set of resources', () => {
  for (const n of names) {
    for (const [kind, name] of [['ServiceAccount', n], ['DestinationRule', n], ['VirtualService', n], ['Sidecar', n], ['AuthorizationPolicy', `allow-${n}`], ['NetworkPolicy', `allow-ingress-${n}`]])
      assert.ok(of(kind).some((d) => d.metadata.name === name), `${kind}/${name}`);
  }
  assert.ok(of('NetworkPolicy').some((d) => d.metadata.name === 'default-deny' && d.spec.policyTypes.includes('Egress') && d.spec.policyTypes.includes('Ingress')));
});

test('circuit breakers: every service sheds load fast and ejects bad instances without emptying the pool', () => {
  for (const dr of of('DestinationRule')) {
    const t = dr.spec.trafficPolicy, od = t.outlierDetection, cp = t.connectionPool;
    assert.ok(od.consecutive5xxErrors >= 1 && od.consecutive5xxErrors <= 10, `${dr.metadata.name}: ejection threshold sane`);
    assert.ok(od.maxEjectionPercent <= 50, `${dr.metadata.name}: never ejects more than half (would turn degradation into outage)`);
    assert.ok(od.minHealthPercent > 0);
    assert.ok(cp.http.http1MaxPendingRequests <= 100 && cp.tcp.maxConnections > 0, `${dr.metadata.name}: bounded queue = fail fast`);
    assert.ok(ms(od.baseEjectionTime) >= ms(od.interval), 'ejection lasts at least one analysis interval');
    assert.equal(od.splitExternalLocalOriginErrors, true);
  }
});

test('retries are safe: never on writes, never on 5xx/timeouts, and they fit the time budget', () => {
  for (const vs of of('VirtualService').filter((d) => names.includes(d.metadata.name))) {
    const s = svc(vs.metadata.name);
    for (const r of vs.spec.http) {
      const methods = r.match[0].method.regex.split('|'), retries = r.retries;
      if (methods.some((m) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)) && !(s.routes.find((x) => x.name === r.name)?.retries)) assert.equal(retries.attempts, 0, `${vs.metadata.name}/${r.name}: writes are never retried`);
      if (retries.attempts > 0) {
        assert.ok(!/5xx|gateway-error|retriable|timeout/.test(retries.retryOn), `${vs.metadata.name}: no retry on 5xx/timeouts (retry storms)`);
        assert.ok(retries.attempts <= 2);
        if (retries.perTryTimeout) assert.ok(ms(retries.perTryTimeout) * (retries.attempts + 1) <= ms(r.timeout) + 1, 'tries fit inside the route timeout');
      }
    }
  }
  assert.ok(!c.services['sentinelmesh-api'].routes.find((r) => r.name === 'write').retries, 'API writes (approvals, rotations) are never auto-retried');
});

test('deadline budget: each caller waits longer than its callee, up to the edge gateway', () => {
  for (const [n, s] of Object.entries(c.services)) for (const caller of s.callers) {
    if (caller === 'gateway') continue;
    assert.ok(ms(svc(caller).timeout) > ms(svc(n).timeout), `${caller} (${svc(caller).timeout}) must outlast ${n} (${svc(n).timeout})`);
  }
  for (const r of c.gateway.routes) assert.ok(ms(c.gateway.timeout) > ms(svc(r.to).timeout), `gateway outlasts ${r.to}`);
});

test('the call graph is acyclic (cycles amplify load and deadlock deadlines)', () => {
  const colour = {};
  const visit = (n, path) => {
    assert.notEqual(colour[n], 1, `cycle: ${[...path, n].join(' -> ')}`);
    if (colour[n] === 2) return; colour[n] = 1;
    for (const t of c.services[n].egressTo ?? []) visit(t, [...path, n]);
    colour[n] = 2;
  };
  names.forEach((n) => visit(n, []));
});

test('edge: tenant comes only from a verified JWT claim, and requests without it are refused', () => {
  const ra = of('RequestAuthentication')[0].spec.jwtRules[0];
  assert.deepEqual(ra.outputClaimToHeaders, [{ header: 'x-tenant', claim: c.gateway.jwt.tenantClaim }]);
  assert.ok(ra.audiences?.length && ra.issuer.startsWith('https://'));
  const pol = of('AuthorizationPolicy').find((d) => d.metadata.name === 'gateway-require-tenant-jwt');
  assert.equal(pol.spec.action, 'ALLOW');
  assert.ok(JSON.stringify(pol.spec.rules[0].when).includes(`request.auth.claims[${c.gateway.jwt.tenantClaim}]`));
  const gw = of('Gateway')[0];
  assert.equal(gw.spec.servers[0].tls.minProtocolVersion, 'TLSV1_2');
  assert.equal(gw.spec.servers[1].tls.httpsRedirect, true);
  // x-tenant is never stripped by a route rule: that would run AFTER the JWT filter set it
  for (const r of of('VirtualService').flatMap((v) => v.spec.http)) assert.ok(!(r.headers?.request?.remove ?? []).includes('x-tenant'));
});

test('observability: access logs and traces carry request id, tenant and trace context', () => {
  const fmt = operator(c).spec.meshConfig.accessLogFormat;
  for (const k of ['X-REQUEST-ID', 'X-TENANT', 'TRACEPARENT']) assert.ok(fmt.includes(k), `access log has ${k}`);
  const tags = of('Telemetry')[0].spec.tracing[0].customTags;
  assert.equal(tags.tenant.header.name, 'x-tenant'); assert.equal(tags.request_id.header.name, 'x-request-id');
  for (const h of ['x-request-id', 'x-tenant', 'traceparent']) assert.ok(c.propagate.includes(h));
});

test('sidecars only expose declared dependencies', () => {
  for (const sc of of('Sidecar')) {
    const hosts = sc.spec.egress[0].hosts, s = c.services[sc.metadata.name];
    for (const t of s.egressTo ?? []) assert.ok(hosts.some((h) => h.includes(`${t}.`)));
    const others = names.filter((n) => n !== sc.metadata.name && !(s.egressTo ?? []).includes(n));
    for (const o of others) assert.ok(!hosts.some((h) => h.includes(`/${o}.`) || h.includes(`./${o}.`)), `${sc.metadata.name} must not see ${o}`);
    assert.equal(sc.spec.outboundTrafficPolicy.mode, 'REGISTRY_ONLY');
  }
});
