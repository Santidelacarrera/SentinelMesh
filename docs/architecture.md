# Arquitectura de SentinelMesh — Nexus Security & AI Lab

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
| Persistencia | Repositorios **async** (`Repo<T>`): `MemoryRepo` (dev/tests) o `PgRepo` (con `DATABASE_URL`). Sin caché en proceso: cada lectura/escritura va a PostgreSQL dentro de una transacción con `app.org_id` (RLS). Escrituras atómicas con `SELECT … FOR UPDATE`, altas únicas con índices únicos, cadena de auditoría con `pg_advisory_xact_lock` por organización | Postgres 16 real con **dos instancias de la API** sobre la misma BD: la réplica B ve y completa lo que inició la A; doble decisión simultánea → 200 + 409; ingestas concurrentes crean cada hallazgo una vez; cadena de auditoría lineal con escritores concurrentes; RLS y tablas append-only |
| Autenticación | OIDC/JWT (`jose`, JWKS): issuer, audience, expiración, algoritmos permitidos, claims de org y rol | Tokens firmados con claves de prueba: alg=none, HS256, otra clave, issuer/aud incorrectos, rol desconocido, sin tenant |
| Firma de aprobaciones | `SignatureBackend`: HMAC (dev), **Ed25519** (verificación solo con clave pública) o **AWS KMS** ECDSA (la clave no sale del HSM) | KMS contra moto; las firmas de rechazo no sirven como aprobación |
| Varios workers | `ExecutionLock` (Redis `SET NX PX` + token, liberación atómica); si está ocupado lanza error y la cola reintenta | Redis real: exclusión, expiración, un holder obsoleto no libera el lock de otro; test de carrera de 3 `advance` |

Configuración: `INFRA_MODE=aws` activa los adaptadores reales (con `NODE_ENV=production` es **obligatorio**; sin él la app no arranca).
Variables: `DATABASE_URL`, `REDIS_URL`, `OBJECT_STORE_BUCKET`/`AWS_ENDPOINT_URL`, `OIDC_ISSUER`/`OIDC_AUDIENCE`/`OIDC_JWKS_URI`/`AUTH_ALLOW_API_KEYS=0`,
`APPROVAL_KMS_KEY_ID` | `APPROVAL_ED25519_PRIVATE_KEY` | `APPROVAL_SIGNING_KEY`, `HEALTHCHECK_URLS`, `ISOLATION_TARGETS`, `PROMETHEUS_URL`, `LOKI_URL`, `KUBE_API_URL`.

## Endurecimiento HTTP y lectura para la consola
Cabeceras de seguridad en toda la API (`nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, CSP restrictiva), límite de tasa por credencial (`RATE_LIMIT_PER_MIN`, 600 por defecto, 429 + `Retry-After`), `GET /healthz`, y endpoints de lectura para la consola (`/me`, `/findings` filtrable y paginado, `/assets`, `/credentials`, `/executions`, `/incidents`, `/iam/audits`, bandeja enriquecida con ejecución y hallazgo de origen). Las credenciales solo se devuelven enmascaradas.

## Varias réplicas de la API
La API es **sin estado**: todo el estado compartido vive fuera del proceso.

| Qué | Dónde | Cómo se evitan las carreras |
|---|---|---|
| Entidades, aprobaciones, ejecuciones | PostgreSQL | `update` = lectura-modificación-escritura bajo bloqueo de fila; la decisión de una aprobación es compare-and-set (la segunda recibe 409); `createUnique` + índices únicos (hallazgo abierto por huella, una aprobación por paso, versión de workflow única, un snapshot forense por incidente) |
| Auditoría | PostgreSQL | un bloqueo asesor por organización serializa «leer último → construir siguiente → insertar»; la carga se normaliza a JSON antes de calcular el hash para que el almacén devuelva exactamente lo hasheado |
| Cola y bloqueos de ejecución | Redis (BullMQ + `SET NX PX`) | un worker por ejecución; si está ocupado se reintenta |
| Evidencia y planes guardados de Terraform | S3/MinIO | clave de escritura única + SHA-256 |
| Estado de Terraform | backend compartido (`TF_BACKEND_HCL`, p. ej. S3 + DynamoDB) | bloqueo de estado de Terraform |

`NODE_ENV=production` **exige** `INFRA_MODE=aws`, `DATABASE_URL`, `REDIS_URL`, `OBJECT_STORE_BUCKET` (y `TF_BACKEND_HCL` si Terraform está activo): sin ellos la app no arranca, para que ninguna réplica use memoria local sin avisar. El límite de peticiones (`RATE_LIMIT_PER_MIN`) es **por réplica**.

## Terraform real en el dry-run
Con `TERRAFORM_ENABLED=1` los planes **waf** e **iam** pasan por Terraform de verdad:
1. Se genera HCL válido y *a prueba de inyección* (nombres y CIDR validados con listas estrictas; `${`/`%{` neutralizados; el HCL se valida con `terraform validate`).
2. `terraform init/validate/plan -out` en un directorio temporal, sin shell, con entorno depurado (la API no filtra sus propios secretos al proceso hijo) y salida redactada. El plan **no cambia nada** en la nube.
3. El analista y el aprobador ven la salida real de `terraform plan` (+ resumen añadir/cambiar/destruir) y el HCL. El plan binario se guarda en el almacén de objetos con su SHA-256.
4. El **hash del plan que firma el aprobador cubre el HCL y los cambios de recursos que calculó Terraform**, no solo nuestra descripción.
5. Tras la firma, el adaptador ejecuta `terraform apply <ese plan guardado>`: Terraform rechaza el plan si la configuración o el estado cambiaron (plan obsoleto). Si se reintenta tras un fallo ya aplicado, un plan nuevo sin cambios cuenta como éxito (idempotente). Un plan o HCL manipulado → fallo terminal, sin tocar la nube.
6. IAM: con «política inline actual» se **importa** esa política y se sustituye su documento in situ, de modo que el plan muestra literalmente «amplia → mínimo privilegio».
En modo Terraform el conjunto de direcciones de la regla WAF es el estado deseado completo (en modo SDK se fusiona con el existente). Aislamiento y rotación siguen usando el adaptador SDK. Variables: `TF_BIN`, `TF_STATE_DIR`, `TF_BACKEND_HCL`, `TF_PROVIDER_HCL`, `TF_AWS_VERSION`, `TF_CLI_CONFIG_FILE`, `TF_PASS_ENV`, `TF_TIMEOUT_MS`.
Verificado con el binario de Terraform 1.9.8 y el proveedor AWS 5.82 contra moto: plan determinista y de solo lectura, aplicación del plan guardado, repetición idempotente, importación de política IAM, plan manipulado rechazado, entradas hostiles rechazadas.

## Límites conocidos (honestidad)
- Las lecturas con filtros complejos (p. ej. `/findings?q=`) hacen un escaneo de la organización y filtran en el proceso; las búsquedas por igualdad usan el índice GIN. Para volúmenes muy grandes habría que empujar filtros y paginación a SQL.
- Moto reproduce la API de AWS, no todas sus reglas (propagación de IAM, cuotas…). Conviene ejecutar `aws.spec.ts` y `terraform.spec.ts` contra una cuenta sandbox antes de producción.
- El forense (Prometheus/Loki/Kubernetes) se probó con dobles con la forma de sus respuestas, no con servicios reales.
- `CredentialIssuer` por defecto genera valores aleatorios en Secrets Manager; para rotar claves IAM, usuarios de BD o APIs de terceros hay que implementar el emisor de cada sistema.
- Docker no se ejecutó (sin daemon); el Dockerfile se validó paso a paso fuera de Docker.
- Si una ejecución agota los reintentos de la cola, queda en `running` hasta que se reintente manualmente (BullMQ conserva el trabajo fallido).
