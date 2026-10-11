# SentinelMesh como malla de servicios para «Segundo Cerebro»

Diseño y configuración de la capa de red entre microservicios: **identidad y cifrado mutuo (mTLS)**, **políticas de tráfico con circuit breakers**
y **trazabilidad distribuida**. Implementado sobre Istio (sidecars Envoy) + NetworkPolicy de Kubernetes.

> **Supuestos a confirmar.** Solo conocemos con certeza `ContextRAG_Engine` y `ShadowAPI_Guard` (nombres de Kubernetes: `contextrag-engine`, `shadowapi-guard`)
> y los componentes de SentinelMesh (`sentinelmesh-api`, `sentinelmesh-analytics`, `sentinelmesh-web`). Las **aristas entre ellos** (quién llama a quién) son una
> propuesta razonable y viven en un único fichero, [`infra/mesh/services.yaml`](../infra/mesh/services.yaml). Añadir o corregir un servicio es editar ese fichero y ejecutar
> `npm run mesh:gen`; el resto (mTLS, default-deny, circuit breaker, sidecar acotado…) se genera solo y se valida.

## 1. Arquitectura

```
Internet ─TLS 1.2+─►  istio-ingressgateway  ── valida JWT (iss/aud/exp) ── X-Tenant := claim «tenant» del token
                         │  (identidad SPIFFE …/istio-system/sa/istio-ingressgateway-service-account)
                         ▼   mTLS (certs SPIFFE de Istio, rotación automática)
        ┌──────────────────────────────── namespace segundo-cerebro (STRICT, default-deny) ───────────────────────────────┐
        │  shadowapi-guard ──POST /v1/query,/v1/embed──► contextrag-engine                                                  │
        │        │                                                                                                          │
        │        └──POST /api/v1/incidents/trigger──► sentinelmesh-api ──POST,GET /v1/*──► sentinelmesh-analytics            │
        │  sentinelmesh-web (estático, GET/HEAD)            │                                                               │
        └───────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────┘
                                                            └─► egress permitido: AWS (Secrets/WAF), Postgres, Redis, OTel collector
```
Dos capas independientes (defensa en profundidad): **Istio** decide por *identidad criptográfica* y **NetworkPolicy** decide por *red* (L3/L4). Si el sidecar falla o
se omite, la NetworkPolicy sigue cerrando; si alguien alcanza el pod, mTLS + AuthorizationPolicy siguen exigiendo identidad.

Matriz completa (generada): [`infra/mesh/generated/AUTHZ-MATRIX.md`](../infra/mesh/generated/AUTHZ-MATRIX.md).

## 2. mTLS y autorización por identidad
| Control | Configuración | Por qué |
|---|---|---|
| mTLS estricto | `PeerAuthentication` STRICT a nivel de **malla**, de **namespace** y de **cada workload** | Un cambio accidental en un nivel no abre los demás. El test falla si aparece cualquier PERMISSIVE/DISABLE |
| Origen de mTLS | Todos los `DestinationRule` con `tls.mode: ISTIO_MUTUAL` | El cliente siempre presenta su certificado, no depende de auto-mTLS |
| Identidad | SPIFFE: `cluster.local/ns/segundo-cerebro/sa/<servicio>`. Una `ServiceAccount` por servicio, sin token montado | Se autoriza a *quién eres*, no a *dónde estás* (la IP no es identidad) |
| Default-deny | `AuthorizationPolicy` vacía en el namespace | Lo no declarado está denegado |
| Allow mínimo | Una `AuthorizationPolicy ALLOW` por servicio: **principals** de sus llamantes declarados + puerto + métodos + rutas. Sin comodines | `shadowapi-guard` solo puede hacer `POST /api/v1/incidents/trigger` en `sentinelmesh-api`, no leer hallazgos ni aprobar |
| Egress cerrado | `outboundTrafficPolicy: REGISTRY_ONLY` + `Sidecar` por servicio + `ServiceEntry` solo para dependencias externas declaradas | Un servicio comprometido no puede exfiltrar a un destino arbitrario ni siquiera «ver» servicios que no usa |
| Ciclo de vida de certificados | Emitidos por istiod, TTL corto y rotación automática (`trustDomain` fijado) | Sin claves de larga vida que robar o revocar |

## 3. Políticas de tráfico y circuit breakers
Parámetros por defecto (`defaults.circuit`, sobreescribibles por servicio):

| Parámetro | Valor | Efecto / razonamiento |
|---|---|---|
| `http1MaxPendingRequests` | 50 | Cola corta: ante saturación se responde **503 inmediato** en vez de acumular latencia que se propaga aguas arriba |
| `maxConnections` / `http2MaxRequests` | 100 / 200 | Límite de carga por destino (bulkhead): un llamante no puede monopolizar un servicio |
| `consecutive5xxErrors` (+ gateway + local-origin) | 5 (3 en `contextrag-engine`, más caro por petición) | Tras N fallos seguidos la **instancia** se expulsa del balanceo |
| `baseEjectionTime` | 30 s, creciente por reincidencia | Backoff automático: una instancia que reincide pasa más tiempo fuera |
| `maxEjectionPercent` / `minHealthPercent` | 50 / 30 | **Nunca aísla más de la mitad**: si todo el servicio degrada, seguir sirviendo al 50 % es mejor que un apagón por exceso de celo |
| `loadBalancer` | `LEAST_REQUEST` | Una instancia lenta recibe menos tráfico antes de llegar a fallar |
| `splitExternalLocalOriginErrors` | true | Distingue «el servicio respondió 5xx» de «no pude conectar»: reacciona a ambos |

**Cómo se evita el fallo en cascada** (no basta con un circuit breaker):
1. **Presupuesto de tiempo estrictamente decreciente**: cada llamante espera *más* que su llamado (`gateway 12 s > guard 8 s > rag 5 s`; `api 6 s > analytics 2 s`). Si no, el llamante da por muerto lo que aún está trabajando y reintenta → amplificación. Un test falla si se invierte.
2. **Los reintentos comparten el presupuesto** de la ruta (no lo multiplican por salto) y solo se hacen ante `connect-failure, refused-stream, unavailable, reset`: fallos rápidos y seguros. **Nunca ante 5xx ni timeouts** (reintentar a un servicio lento lo hunde: tormenta de reintentos).
3. **Las escrituras jamás se reintentan solas** (`POST/PUT/PATCH/DELETE` en la API: aprobaciones, rotaciones, firmas). Solo lecturas e idempotentes declaradas (p. ej. `POST /v1/query` del RAG es solo lectura).
4. **Grafo de llamadas acíclico**: un ciclo amplifica carga y compromete los plazos. Un test lo detecta.
5. **Degradación elegante en la aplicación**: `sentinelmesh-api` tiene un breaker propio hacia `analytics` (3 fallos ⇒ 15 s sin llamar, usa el cálculo local equivalente). Un analytics caído cuesta 3 timeouts, no uno por petición.

## 4. Trazabilidad distribuida
**Qué hace la malla y qué no.** Envoy genera `x-request-id` y los spans y los exporta por OTLP al collector. **No puede copiar cabeceras** de la petición entrante a las llamadas
salientes que hace tu código: eso es responsabilidad de cada servicio. Por eso hay un contrato explícito (`propagate` en `services.yaml`):

| Cabecera | Origen | Garantía |
|---|---|---|
| `x-request-id` | Envoy en el borde (o el cliente, si es válido) | Se conserva en todos los saltos; si falta o es inválida se **genera**; se devuelve al cliente para citarla en soporte |
| `x-tenant` | **Gateway**, a partir del claim `tenant` del JWT **ya verificado** (`outputClaimToHeaders` sobrescribe lo que envíe el cliente) | No falsificable desde fuera. Sin JWT con ese claim el gateway no deja pasar la petición. La API exige además que coincida con la organización autenticada (`MESH_ENFORCE_TENANT=1` la hace obligatoria) |
| `traceparent`, `tracestate`, `baggage`, `b3` | Envoy / cliente | Propagadas tal cual (W3C Trace Context) |

Implementación en la aplicación (probada): `apps/api/src/common/correlation.ts` y `services/analytics/app/correlation.py`:
- se valida el formato (bloquea inyección en logs/cabeceras) y solo se reenvía la **lista blanca**: jamás `authorization`, `x-api-key` ni cookies;
- el contexto es por petición (AsyncLocalStorage / contextvars), sin fugas entre peticiones concurrentes;
- solo se adjunta a llamadas a **otros servicios de la malla**, no a AWS ni a terceros;
- **atraviesa la cola asíncrona**: la ejecución guarda el `request id` de origen y el worker continúa bajo él, de modo que auditoría y llamadas del worker correlacionan con la petición que las originó;
- cada entrada de auditoría incluye `requestId`; los logs de acceso de Envoy (`%REQ(X-REQUEST-ID)%`, `%REQ(X-TENANT)%`, `traceparent`, identidad del par, versión TLS) y los spans llevan `tenant` y `request_id` como etiquetas. Muestreo 10 % general y 100 % en `sentinelmesh-api`.
**Regla para los servicios nuevos de Segundo Cerebro:** al hacer una llamada saliente a otro servicio de la malla, reenviar las cabeceras de `propagate` (usar el helper de su lenguaje) y registrar `x-request-id` en el log.

## 5. Despliegue y operación
1. Instalar Istio con `generated/05-istio-operator.yaml` (REGISTRY_ONLY, logs JSON, proveedor OTLP) y aplicar `generated/*.yaml` en orden numérico.
2. **Migración sin cortes de un namespace existente:** primero sidecars con `PeerAuthentication` PERMISSIVE → comprobar con métricas (`istio_requests_total{connection_security_policy!="mutual_tls"}` a 0) → aplicar STRICT. Esta carpeta emite **solo STRICT** a propósito (el test impide lo contrario); la fase PERMISSIVE es una acción temporal y manual.
3. Rotar JWKS/emisor: editar `gateway.jwt` y regenerar. Certificados del borde: cert-manager (`sc-gateway-tls`).
4. Comprobaciones antes de cada despliegue: `infra/mesh/validate.sh` (también en CI).

Síntomas frecuentes: `503 UC / "upstream connect error"` → mTLS no negociado (¿pod sin sidecar hablando a un servicio STRICT?); `503 UO` → circuit breaker saturado (revisar `connectionPool`/capacidad, no subir límites sin mirar al servicio); `403 RBAC: access denied` → arista no declarada en `services.yaml`; `401` en el borde → JWT inválido o sin claim `tenant`.

## 6. Verificación
| Qué | Cómo | Resultado |
|---|---|---|
| Esquema de los 51 recursos | `kubeconform --strict` con los CRD de Istio | 51 válidos |
| Semántica de Istio | `istioctl analyze --failure-threshold Warning` | sin avisos (detectó y corregí `ServiceEntry` TCP sin direcciones) |
| Operador | `istioctl manifest generate` | renderiza |
| Invariantes de seguridad (11) | `node --test`: STRICT en todos los niveles, default-deny, allows = grafo declarado, sin comodines, mínimo privilegio, presupuesto de tiempo, sin reintentos de escrituras, circuit breakers acotados, grafo acíclico, tenant solo desde JWT, logs con ids, sidecars acotados | pasan; **cada una detecta una mutación** (probado: invertir plazos, `maxEjectionPercent: 100`, reintentar escrituras, arista no declarada) |
| Propagación en la app | 6 tests Node + 4 Python | pasan |
| Breaker de cliente | 3 tests | pasan |

**No verificado (no hay clúster aquí):** el comportamiento real de Envoy (expulsión de instancias, 503 por desbordamiento, reintentos), la emisión de certificados y la exportación OTLP. Antes de producción hay que ejecutar en un clúster de pruebas un ejercicio de caos (matar instancias, inyectar latencia/errores con `fault` de Istio) y confirmar que no hay cascada.

## 7. Límites y decisiones abiertas
- Los límites de circuit breaker son **valores de partida** razonados, no medidos: calibrar con carga real (p. ej. `http2MaxRequests` según la concurrencia por pod).
- Istio no tiene presupuesto de reintentos (`retry budget`) como Linkerd: por eso se limitan a 2 intentos, solo fallos de conexión y dentro del plazo total.
- `x-tenant` por cabecera es un **dato de correlación y de comprobación cruzada**, no la fuente de autorización: la API sigue autorizando por credencial y organización.
- Los servicios fuera de la malla (Postgres/Redis gestionados) no tienen mTLS de malla: usar TLS propio de esos servicios.
- Modo *ambient* de Istio (sin sidecars) o Linkerd serían alternativas; el catálogo y las invariantes son agnósticos, el generador no.
