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

## Estado de la implementación (honestidad)
- **Probado**: lógica de dominio, API HTTP, motor, cola BullMQ contra Redis real, servicio Python, contrato TS↔Python.
- **Simulado**: `SecretProvider`, `HealthChecker`, `InfraAdapter`, `ForensicCollector` (`workflow/simulated.ts`). Los adaptadores reales (AWS Secrets Manager/Vault, WAFv2, K8s) implementan las mismas interfaces en `workflow/ports.ts`.
- **No ejecutado aquí**: `db/schema.sql` (se validó que parsea; el runtime usa el almacén en memoria con la misma API por organización), imágenes Docker/compose, adaptador S3/MinIO (hay backend en memoria y de disco con el mismo contrato `ObjectStorage`).
- **Pendiente para producción**: persistencia Postgres, autenticación real (OIDC) en lugar de API keys, firma asimétrica/KMS de aprobaciones, bloqueo distribuido por ejecución al escalar a varios workers, `terraform plan` real en el dry-run.
