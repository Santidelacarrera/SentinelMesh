# Arquitectura de SentinelMesh

```
 scanners / gateways ──► API (NestJS) ──► Analytics (FastAPI)
  (SARIF, Trivy, ZAP,      │  ▲             correlación · menor privilegio · resumen forense con citas
   Semgrep, secrets,       │  │
   anomalías)              ▼  │
                    Motor de orquestación ── cola (BullMQ/Redis)
                    pasos idempotentes · reintentos · pausa en aprobación
                           │                      ▲
              puertos ◄────┘                      │ decisión firmada (HMAC sobre planHash)
   SecretProvider · HealthChecker · InfraAdapter · ForensicCollector      Bandeja SecOps (React)
```

## Componentes (`apps/api/src`)

| Módulo | Responsabilidad |
|---|---|
| `ingest/` | Parsers SARIF/Trivy/Semgrep/ZAP/secrets (validados con zod), dedupe por fingerprint, correlación con `AssetContext`, supresión de falsos positivos, archivado del reporte **ya redactado**. |
| `analytics/` | Cliente del servicio Python con timeout y fallback local idéntico (contrato verificado). |
| `remediation/dryrun.service.ts` | Genera diffs y HCL de Terraform. **No depende de ningún adaptador de infraestructura**: no puede tener efectos. |
| `workflow/` | Definiciones versionadas e inmutables; motor reanudable; handlers de acciones; puertos y simulados. |
| `approvals/` | Bandeja, decisión firmada, separación de funciones, firma verificable por los adaptadores. |
| `incidents/` | Disparadores de anomalías, snapshot forense write-once con SHA-256, resumen. |
| `audit/` | Traza append-only encadenada por hash, con redacción previa. |
| `store/` | Almacén con **orgId obligatorio en cada operación** (equivalente a RLS en `db/schema.sql`). |

## Garantías de seguridad y dónde se prueban

| Garantía | Mecanismo | Prueba (`apps/api/test/e2e.spec.ts`) |
|---|---|---|
| Ninguna acción destructiva sin aprobación | (1) El paso se declara `destructive` (la publicación del workflow lo exige para acciones destructivas); (2) el motor pausa y solo continúa con una aprobación cuya firma HMAC verifica y cuyo `planHash` coincide; (3) los adaptadores re-verifican la prueba y rechazan llamadas sin ella | `IAM trimming … waits for the signed decision`, `forged approvals cannot unlock adapters` |
| Lo aprobado es lo ejecutado | `planHash` = SHA-256 del plan; se recomprueba antes de ejecutar | `refuses to execute a plan tampered with…` |
| Separación de funciones | Quien solicita no puede aprobar | `separation of duties…` |
| Zero-downtime | Nueva versión → store apuntado → healthcheck → (aprobación) → revocar. Si falla el healthcheck: rollback al valor anterior y el viejo nunca se toca. Nunca se revoca la versión activa | `rotates … only after approval`, `rolls back and never revokes…` |
| Resiliencia | Pasos idempotentes (`idempotencyKey`), estado persistido, `advance` re-entrante, reintentos acotados | `survives a worker crash…`, `restarted worker resumes…`, `gives up after bounded retries` |
| Aislamiento por organización | Toda lectura/escritura exige `orgId`; ids ajenos → 404 | `isolates organisations` |
| Enmascarado de secretos | `redact()` en audit trail, outputs de pasos, forense y reporte archivado; solo se persiste la forma enmascarada | `masks leaked secrets everywhere…` |
| SSRF / validación | zod `.strict()` en todas las entradas; la URL del servicio de analítica es config del operador; `assertSafeUrl` bloquea IPs privadas/metadata para cualquier URL saliente derivada de datos | `unit.spec.ts › SSRF defence`, `validates the webhook schema strictly` |
| Evidencia inalterable | Clave write-once + SHA-256 verificado en cada lectura | `detects tampering of the frozen evidence` |

## Flujo de rotación (zero-downtime)
1. `create_credential` — nueva versión (idempotente por `executionId:step`).
2. `update_secret_store` — se apunta el gestor de secretos a la nueva versión (la vieja sigue válida).
3. `healthcheck` — 3 intentos; si falla → rollback + ejecución `failed`.
4. `revoke_credential` — **requiere aprobación**; revoca solo la versión previa y solo si la activa es válida.

## Flujo de incidente
`POST /incidents/trigger` → umbral por minuto (fuerza bruta ≥ 10/min, pico ≥ 600/min) → incidente + plan de aislamiento (dry-run) →
workflow `incident-response`: `collect_forensics` (inmediato, congelado) → `summarize` (cada línea cita su evidencia) →
`isolate_service` (**pausa**) → `notify`.

## Adaptadores reales y cómo se verificaron

| Pieza | Implementación | Verificación |
|---|---|---|
| Secretos | `AwsSecretProvider` (Secrets Manager: versiones = etiquetas `sm-vN`, `AWSCURRENT` = activa, idempotencia por `ClientRequestToken`) | Contra **moto** (emulador de la API de AWS): crear idempotente, activar, rollback, revocar solo con prueba firmada, nunca la activa |
| WAF / IAM / aislamiento | `AwsInfraAdapter` (WAFv2 IP set + rule group, `PutRolePolicy`, EC2 → SG de cuarentena con tag de rollback) | moto; cada método verifica la prueba de aprobación **antes** de tocar nada, y es idempotente |
| Healthcheck | `HttpHealthChecker`: sondea el servicio con el secreto **candidato**, sin seguir redirects, SSRF-validado, sin filtrar el secreto | Servidor HTTP local que solo acepta ciertas credenciales; flujo completo rotación/rollback sobre Secrets Manager |
| Forense | `HttpForensicCollector` (Prometheus, Loki, API de Kubernetes); fuentes opcionales, huecos registrados, nombre del objetivo validado | **Solo contra dobles con la forma de las respuestas** — no contra Prometheus/Loki/K8s reales |
| Evidencia | `S3ObjectStorage` (S3/MinIO, `forcePathStyle` si hay endpoint) | moto (API S3) |
| Persistencia | `PgPersistence`: escritura inmediata (write-through) en Postgres dentro de transacciones con `app.org_id`; hidratación al arrancar | Postgres 16 real: reinicio con ejecución pendiente que se reanuda y completa, RLS (otra org / sin org → 0 filas, insert cruzado rechazado), auditoría y versiones de workflow append-only |
| Autenticación | OIDC/JWT (`jose`, JWKS): issuer, audience, expiración, algoritmos permitidos, claims de org y rol | Tokens firmados con claves de prueba: alg=none, HS256, otra clave, issuer/aud incorrectos, rol desconocido, sin tenant |
| Firma de aprobaciones | `SignatureBackend`: HMAC (dev), **Ed25519** (verificación solo con clave pública) o **AWS KMS** ECDSA (la clave no sale del HSM) | KMS contra moto; las firmas de rechazo no sirven como aprobación |
| Varios workers | `ExecutionLock` (Redis `SET NX PX` + token, liberación atómica); si está ocupado lanza error y la cola reintenta | Redis real: exclusión, expiración, un holder obsoleto no libera el lock de otro; test de carrera de 3 `advance` |

Configuración: `INFRA_MODE=aws` activa los adaptadores reales (con `NODE_ENV=production` es **obligatorio**; sin él la app no arranca).
Variables: `DATABASE_URL`, `REDIS_URL`, `OBJECT_STORE_BUCKET`/`AWS_ENDPOINT_URL`, `OIDC_ISSUER`/`OIDC_AUDIENCE`/`OIDC_JWKS_URI`/`AUTH_ALLOW_API_KEYS=0`,
`APPROVAL_KMS_KEY_ID` | `APPROVAL_ED25519_PRIVATE_KEY` | `APPROVAL_SIGNING_KEY`, `HEALTHCHECK_URLS`, `ISOLATION_TARGETS`, `PROMETHEUS_URL`, `LOKI_URL`, `KUBE_API_URL`.

## Límites conocidos (honestidad)
- **Un solo proceso escritor**: las colecciones en memoria son la ruta de lectura y Postgres es escritura inmediata + hidratación al arrancar. Varias réplicas de la API no verían las escrituras de las otras; para escalar horizontalmente hay que pasar los repositorios a async leyendo de Postgres (el esquema y el RLS ya están listos). El lock evita doble ejecución, pero no resuelve esa visibilidad.
- Si una escritura a Postgres falla se registra y `flush()` lanza; no hay cola de reintento persistente para escrituras.
- Los emuladores (moto) reproducen la API de AWS, no todas sus reglas (IAM propagation, cuotas, ModifyInstanceAttribute en VPC reales…). Antes de producción conviene correr la suite de `aws.spec.ts` contra una cuenta sandbox.
- `CredentialIssuer` por defecto genera valores aleatorios en Secrets Manager; para rotar credenciales reales (claves IAM, usuarios de BD, APIs de terceros) hay que implementar el emisor de cada sistema.
- El Dockerfile de la API se validó paso a paso fuera de Docker (instalación limpia, build, instalación solo-producción y arranque en `NODE_ENV=production`); no hay daemon Docker en este entorno, así que `docker compose up` no se ejecutó (sí `docker compose config`).
- Frontend: sin tests automatizados (compila y se probó la API que consume).
- `terraform plan` real en el dry-run sigue pendiente: hoy se genera el HCL y el diff, no se ejecuta Terraform.
