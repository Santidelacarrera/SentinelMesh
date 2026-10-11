#!/usr/bin/env node
// Genera la configuración de Istio + NetworkPolicy desde services.yaml.  Uso: node infra/mesh/generate.mjs [--check]
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, stringify } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
export const loadCatalog = (p = join(here, 'services.yaml')) => parse(readFileSync(p, 'utf8'));

const dur = (s) => { const m = /^(\d+)(ms|s|m)$/.exec(String(s)); if (!m) throw new Error(`bad duration ${s}`); return Number(m[1]) * { ms: 1, s: 1000, m: 60000 }[m[2]]; };
export const ms = dur;
const inCluster = (h) => h.endsWith('.svc.cluster.local');   // ya está en el registro de Kubernetes: no necesita ServiceEntry
const labels = (name) => ({ app: name, 'app.kubernetes.io/part-of': 'segundo-cerebro' });
const principal = (c, sa) => `${c.trustDomain}/ns/${c.namespace}/sa/${sa}`;
const GW_SA = 'istio-ingressgateway-service-account';   // identidad del gateway de entrada (ns istio-system)
const gwPrincipal = (c) => `${c.trustDomain}/ns/istio-system/sa/${GW_SA}`;

export function merged(c, svc) {
  const d = c.defaults;
  return { ...svc, circuit: { ...d.circuit, ...(svc.circuit ?? {}) }, retries: { ...d.retries, ...(svc.retries ?? {}) }, timeout: svc.timeout ?? d.timeout };
}

export function build(c) {
  const ns = c.namespace, out = {};
  const add = (file, doc) => { (out[file] ??= []).push(doc); };
  const svcs = Object.fromEntries(Object.entries(c.services).map(([n, s]) => [n, merged(c, s)]));
  const meta = (kind, apiVersion, name, namespace = ns, extra = {}) => ({ apiVersion, kind, metadata: { name, namespace, labels: { 'app.kubernetes.io/part-of': 'segundo-cerebro', 'app.kubernetes.io/managed-by': 'mesh-generator' }, ...extra } });

  // ── 00 namespace + identidad ──
  add('00-namespace.yaml', { apiVersion: 'v1', kind: 'Namespace', metadata: { name: ns, labels: { 'istio-injection': 'enabled', 'pod-security.kubernetes.io/enforce': 'restricted' } } });
  for (const n of Object.keys(svcs)) add('00-namespace.yaml', { apiVersion: 'v1', kind: 'ServiceAccount', metadata: { name: n, namespace: ns, labels: labels(n) }, automountServiceAccountToken: false });

  // ── 10 mTLS estricto ──
  add('10-mtls.yaml', { ...meta('PeerAuthentication', 'security.istio.io/v1', 'default', 'istio-system'), spec: { mtls: { mode: 'STRICT' } } });          // toda la malla
  add('10-mtls.yaml', { ...meta('PeerAuthentication', 'security.istio.io/v1', 'default'), spec: { mtls: { mode: 'STRICT' } } });                         // y el namespace, explícito
  for (const [n, s] of Object.entries(svcs)) {
    if (s.probes === false) continue;
    // kubelet no habla mTLS: las sondas se reescriben por el sidecar, y aun así el puerto de la app exige mTLS.
    add('10-mtls.yaml', { ...meta('PeerAuthentication', 'security.istio.io/v1', `${n}-strict`), spec: { selector: { matchLabels: { app: n } }, mtls: { mode: 'STRICT' } } });
  }

  // ── 20 autorización: default-deny + permitir solo las aristas declaradas (identidad SPIFFE, no IP) ──
  add('20-authz.yaml', { ...meta('AuthorizationPolicy', 'security.istio.io/v1', 'deny-all'), spec: {} });                                                    // sin reglas = nada permitido
  for (const [n, s] of Object.entries(svcs)) {
    const rules = s.callers.map((caller) => {
      const from = caller === 'gateway' ? gwPrincipal(c) : principal(c, caller);
      const a = (s.allow ?? {})[caller === 'gateway' ? 'gateway' : caller];
      const op = a ? { ...(a.methods ? { methods: a.methods } : {}), ...(a.paths ? { paths: a.paths } : {}), ports: [String(s.port)] } : { ports: [String(s.port)] };
      return { from: [{ source: { principals: [from] } }], to: [{ operation: op }] };
    });
    add('20-authz.yaml', { ...meta('AuthorizationPolicy', 'security.istio.io/v1', `allow-${n}`), spec: { selector: { matchLabels: { app: n } }, action: 'ALLOW', rules } });
  }

  // ── 30 resiliencia: circuit breaker + timeouts + reintentos seguros ──
  for (const [n, s] of Object.entries(svcs)) {
    const ci = s.circuit, host = `${n}.${ns}.svc.cluster.local`;
    add('30-traffic.yaml', { ...meta('DestinationRule', 'networking.istio.io/v1', n), spec: {
      host, trafficPolicy: {
        tls: { mode: 'ISTIO_MUTUAL' },
        connectionPool: { tcp: { maxConnections: ci.maxConnections, connectTimeout: '1s' }, http: { http1MaxPendingRequests: ci.http1MaxPendingRequests, http2MaxRequests: ci.http2MaxRequests, maxRequestsPerConnection: ci.maxRequestsPerConnection, maxRetries: 3, idleTimeout: '60s' } },
        outlierDetection: { consecutive5xxErrors: ci.consecutive5xx, consecutiveGatewayErrors: ci.consecutive5xx, interval: ci.interval, baseEjectionTime: ci.baseEjectionTime, maxEjectionPercent: ci.maxEjectionPercent, minHealthPercent: ci.minHealthPercent, splitExternalLocalOriginErrors: true, consecutiveLocalOriginFailures: ci.consecutive5xx },
        loadBalancer: { simple: 'LEAST_REQUEST' },                                                                             // ante una instancia lenta, recibe menos tráfico
      } } });
    const http = (s.routes ?? [{ name: 'all', methods: ['GET', 'POST'], retries: false }]).map((r) => {
      const paths = r.paths ?? [null];
      return {
        name: r.name,
        match: paths.map((p) => ({ method: { regex: r.methods.join('|') }, ...(p ? { uri: p.endsWith('*') ? { prefix: p.slice(0, -1) } : { exact: p } } : {}) })),
        route: [{ destination: { host, port: { number: s.port } } }],
        timeout: s.timeout,
        retries: r.retries ? { attempts: s.retries.attempts, retryOn: s.retries.on, ...(s.retries.perTryTimeout ? { perTryTimeout: s.retries.perTryTimeout } : {}) } : { attempts: 0 },
      };
    });
    add('30-traffic.yaml', { ...meta('VirtualService', 'networking.istio.io/v1', n), spec: { hosts: [host], http } });
  }

  // ── 35 sidecar: cada servicio solo "ve" a quien puede llamar (menos superficie y menos config en Envoy) ──
  for (const [n, s] of Object.entries(svcs)) {
    const hosts = [`istio-system/*`, ...(s.egressTo ?? []).map((t) => `./${t}.${ns}.svc.cluster.local`), `${c.tracing.collector.split('.')[1]}/${c.tracing.collector}`, ...(s.external ?? []).map((e) => inCluster(e.host) ? `${e.host.split('.')[1]}/${e.host}` : `./${e.host}`)];
    add('35-sidecars.yaml', { ...meta('Sidecar', 'networking.istio.io/v1', n), spec: { workloadSelector: { labels: { app: n } }, outboundTrafficPolicy: { mode: 'REGISTRY_ONLY' }, egress: [{ hosts }] } });
  }
  // dependencias externas conocidas = única salida permitida (REGISTRY_ONLY bloquea el resto)
  const seen = new Set();
  for (const s of Object.values(svcs)) for (const e of s.external ?? []) {
    if (inCluster(e.host) || seen.has(e.host)) continue; seen.add(e.host);
    const tcp = e.protocol === 'TCP';
    add('36-egress.yaml', { ...meta('ServiceEntry', 'networking.istio.io/v1', e.host.replace(/[^a-z0-9]+/g, '-').slice(0, 50)), spec: {
      hosts: [e.host], location: 'MESH_EXTERNAL', resolution: 'DNS',
      ports: [{ number: e.port, name: tcp ? 'tcp' : 'tls', protocol: tcp ? 'TCP' : 'TLS' }] } });
  }

  // ── 40 NetworkPolicy (capa L3/L4 independiente de Istio: defensa en profundidad si el sidecar falla o se omite) ──
  add('40-networkpolicy.yaml', { ...meta('NetworkPolicy', 'networking.k8s.io/v1', 'default-deny'), spec: { podSelector: {}, policyTypes: ['Ingress', 'Egress'] } });
  add('40-networkpolicy.yaml', { ...meta('NetworkPolicy', 'networking.k8s.io/v1', 'allow-dns-and-control-plane'), spec: { podSelector: {}, policyTypes: ['Egress'], egress: [
    { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } }, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }], ports: [{ port: 53, protocol: 'UDP' }, { port: 53, protocol: 'TCP' }] },
    { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'istio-system' } } }], ports: [{ port: 15012, protocol: 'TCP' }, { port: 15017, protocol: 'TCP' }] },       // istiod (xDS/CA)
    { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': c.tracing.collector.split('.')[1] } } }], ports: [{ port: c.tracing.collectorPort, protocol: 'TCP' }] },
  ] } });
  for (const [n, s] of Object.entries(svcs)) {
    const from = s.callers.map((cl) => cl === 'gateway'
      ? { namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'istio-system' } }, podSelector: { matchLabels: { istio: 'ingressgateway' } } }
      : { podSelector: { matchLabels: { app: cl } } });
    // 15006 = puerto de entrada del sidecar (inbound), la app solo escucha en loopback para el sidecar
    add('40-networkpolicy.yaml', { ...meta('NetworkPolicy', 'networking.k8s.io/v1', `allow-ingress-${n}`), spec: { podSelector: { matchLabels: { app: n } }, policyTypes: ['Ingress'], ingress: [{ from, ports: [{ port: s.port, protocol: 'TCP' }, { port: 15006, protocol: 'TCP' }] }] } });
    const to = [...(s.egressTo ?? []).map((t) => ({ to: [{ podSelector: { matchLabels: { app: t } } }], ports: [{ port: svcs[t].port, protocol: 'TCP' }, { port: 15006, protocol: 'TCP' }] })),
      ...(s.external ?? []).map((e) => ({ ports: [{ port: e.port, protocol: 'TCP' }] }))];
    if (to.length) add('40-networkpolicy.yaml', { ...meta('NetworkPolicy', 'networking.k8s.io/v1', `allow-egress-${n}`), spec: { podSelector: { matchLabels: { app: n } }, policyTypes: ['Egress'], egress: to } });
  }

  // ── 50 borde: TLS, JWT (identidad del tenant) y cabeceras ──
  const g = c.gateway;
  add('50-gateway.yaml', { ...meta('Gateway', 'networking.istio.io/v1', g.name), spec: { selector: { istio: 'ingressgateway' }, servers: [
    { port: { number: 443, name: 'https', protocol: 'HTTPS' }, hosts: [g.host], tls: { mode: 'SIMPLE', credentialName: g.tlsSecret, minProtocolVersion: 'TLSV1_2' } },
    { port: { number: 80, name: 'http', protocol: 'HTTP' }, hosts: [g.host], tls: { httpsRedirect: true } } ] } });
  add('50-gateway.yaml', { ...meta('VirtualService', 'networking.istio.io/v1', `${g.name}-routes`), spec: { hosts: [g.host], gateways: [g.name], http: g.routes.map((r, i) => ({
    name: `r${i}-${r.to}`, match: [{ uri: { prefix: r.prefix } }], ...(r.rewrite ? { rewrite: { uri: r.rewrite } } : {}), timeout: g.timeout,
    route: [{ destination: { host: `${r.to}.${ns}.svc.cluster.local`, port: { number: svcs[r.to].port } } }],
    headers: { response: { set: { 'strict-transport-security': 'max-age=63072000; includeSubDomains', 'x-content-type-options': 'nosniff' }, remove: ['server', 'x-envoy-upstream-service-time'] } } })) } });
  add('50-gateway.yaml', { ...meta('RequestAuthentication', 'security.istio.io/v1', 'gateway-jwt', 'istio-system'), spec: { selector: { matchLabels: { istio: 'ingressgateway' } }, jwtRules: [{
    issuer: g.jwt.issuer, jwksUri: g.jwt.jwksUri, audiences: g.jwt.audiences, forwardOriginalToken: false,
    // El tenant sale del token VERIFICADO y SOBRESCRIBE cualquier X-Tenant que envíe el cliente.
    outputClaimToHeaders: [{ header: 'x-tenant', claim: g.jwt.tenantClaim }] }] } });
  add('50-gateway.yaml', { ...meta('AuthorizationPolicy', 'security.istio.io/v1', 'gateway-require-tenant-jwt', 'istio-system'), spec: { selector: { matchLabels: { istio: 'ingressgateway' } }, action: 'ALLOW', rules: [
    // sin JWT válido con claim de tenant no entra nada; /healthz y la web estática sí sin token (solo GET)
    { from: [{ source: { requestPrincipals: ['*'] } }], when: [{ key: `request.auth.claims[${g.jwt.tenantClaim}]`, notValues: [''] }] },
    { to: [{ operation: { methods: ['GET', 'HEAD'], paths: ['/', '/assets/*', '/healthz'] } }] } ] } });

  // ── 60 observabilidad ──
  add('60-telemetry.yaml', { ...meta('Telemetry', 'telemetry.istio.io/v1', 'mesh-default', 'istio-system'), spec: {
    tracing: [{ providers: [{ name: 'otel' }], randomSamplingPercentage: c.tracing.samplingPercent, customTags: { tenant: { header: { name: 'x-tenant', defaultValue: 'none' } }, request_id: { header: { name: 'x-request-id', defaultValue: 'none' } } } }],
    accessLogging: [{ providers: [{ name: 'otel' }] }] } });
  add('60-telemetry.yaml', { ...meta('Telemetry', 'telemetry.istio.io/v1', 'sample-everything-on-incident'), spec: { selector: { matchLabels: { app: 'sentinelmesh-api' } }, tracing: [{ providers: [{ name: 'otel' }], randomSamplingPercentage: 100 }] } });

  return out;
}

/** Configuración de la malla (IstioOperator) que Telemetry/Sidecar dan por supuesta. */
export function operator(c) {
  return { apiVersion: 'install.istio.io/v1alpha1', kind: 'IstioOperator', metadata: { name: 'segundo-cerebro-mesh', namespace: 'istio-system' }, spec: { profile: 'default', meshConfig: {
    outboundTrafficPolicy: { mode: 'REGISTRY_ONLY' },
    enableTracing: true,
    accessLogFile: '/dev/stdout',
    accessLogEncoding: 'JSON',
    accessLogFormat: '{"ts":"%START_TIME%","method":"%REQ(:METHOD)%","path":"%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%","code":"%RESPONSE_CODE%","flags":"%RESPONSE_FLAGS%","dur_ms":"%DURATION%","request_id":"%REQ(X-REQUEST-ID)%","tenant":"%REQ(X-TENANT)%","trace_id":"%REQ(TRACEPARENT)%","peer":"%DOWNSTREAM_PEER_URI_SAN%","upstream":"%UPSTREAM_HOST%","tls":"%DOWNSTREAM_TLS_VERSION%"}',
    defaultConfig: { holdApplicationUntilProxyStarts: true, tracing: { sampling: c.tracing.samplingPercent }, proxyMetadata: { ISTIO_META_DNS_CAPTURE: 'true' } },
    extensionProviders: [{ name: 'otel', opentelemetry: { service: c.tracing.collector, port: c.tracing.collectorPort } }],
    trustDomain: c.trustDomain,
  }, values: { global: { proxy: { privileged: false } } } } };
}

/** Matriz de quién puede llamar a quién (para revisión humana; se regenera con el resto). */
export function matrix(c) {
  const rows = [];
  for (const [n, s] of Object.entries(c.services)) for (const caller of s.callers) {
    const a = (s.allow ?? {})[caller];
    rows.push(`| ${caller === 'gateway' ? '**gateway (Internet, con JWT)**' : caller} | ${n}:${s.port} | ${a?.methods?.join(', ') ?? 'todos'} | ${a?.paths?.join(', ') ?? 'todas'} |`);
  }
  return `# Matriz de comunicación (generada)\n\nTodo lo que no está en esta tabla está **denegado** (AuthorizationPolicy default-deny + NetworkPolicy default-deny).\n\n| Origen (identidad SPIFFE) | Destino | Métodos | Rutas |\n|---|---|---|---|\n${rows.join('\n')}\n`;
}

export function render(c) {
  const files = {};
  for (const [f, docs] of Object.entries(build(c))) files[f] = `# GENERADO por infra/mesh/generate.mjs desde services.yaml — no editar a mano.\n` + docs.map((d) => stringify(d, { lineWidth: 0 })).join('---\n');
  files['AUTHZ-MATRIX.md'] = matrix(c);
  files['05-istio-operator.yaml'] = `# GENERADO por infra/mesh/generate.mjs desde services.yaml — no editar a mano.\n` + stringify(operator(c), { lineWidth: 0 });
  return files;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = join(here, 'generated'), files = render(loadCatalog());
  if (process.argv.includes('--check')) {
    let bad = 0;
    for (const [f, body] of Object.entries(files)) { const p = join(dir, f); if (!existsSync(p) || readFileSync(p, 'utf8') !== body) { console.error(`desactualizado: ${f}`); bad++; } }
    if (existsSync(dir)) for (const f of readdirSync(dir)) if (!(f in files)) { console.error(`sobra: ${f}`); bad++; }
    if (bad) { console.error('Ejecuta: npm run mesh:gen'); process.exit(1); }
    console.log('generated/ está al día');
  } else {
    mkdirSync(dir, { recursive: true });
    for (const f of readdirSync(dir)) rmSync(join(dir, f));
    for (const [f, body] of Object.entries(files)) writeFileSync(join(dir, f), body);
    console.log(`${Object.keys(files).length} ficheros en infra/mesh/generated`);
  }
}
