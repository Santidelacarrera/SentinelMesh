# SentinelMesh

Plataforma híbrida **CTEM + higiene IAM + SOAR** con orquestación y **aprobación humana** obligatoria para toda acción destructiva.

Descubre la debilidad (vulnerabilidad o llave expuesta) → evalúa el riesgo real con contexto de aplicación → recolecta evidencia forense →
simula el cambio (diff / Terraform) → ejecuta de forma idempotente **solo tras la firma de un analista SecOps**.

| Capa | Tecnología | Ruta |
|---|---|---|
| API / control plane + motor | NestJS, BullMQ/Redis | `apps/api` |
| Consola SecOps (resumen y mapa de exposición, hallazgos con su porqué, decisiones con firma, ejecuciones, incidentes, identidades, credenciales, auditoría) | React + TypeScript (Vite) | `apps/web` |
| Analítica y contexto | Python + FastAPI | `services/analytics` |
| Datos | PostgreSQL (`db/schema.sql`, RLS), S3/MinIO (contrato `ObjectStorage`) | `db/` |
| Infra | Docker Compose, Terraform de ejemplo | `docker-compose.yml`, `infra/` |

## Probarlo en 1 minuto
```bash
npm install
npm test                      # unitarios + e2e HTTP. Con servicios externos activa más suites (ver abajo)
npm run simulate              # incidente controlado completo, el aprobador APRUEBA
npm run simulate -- --reject  # el aprobador RECHAZA: no cambia nada
cd services/analytics && pip install -r requirements.txt && pytest -q
```
`npm run simulate` ingesta un SARIF y una fuga de credencial, rota la llave con healthcheck (la antigua sigue válida mientras espera),
dispara un brute-force, congela la evidencia, muestra la bandeja con los diffs y aplica/rechaza.

## Arrancar
```bash
docker compose up --build      # api :3000, redis, postgres, minio, analytics
npm run dev -w apps/api        # o sin Docker (cola en memoria, servicios simulados)
npm run demo                   # API con una organización de ejemplo ya cargada (:3000)
npm run dev -w apps/web        # consola en :5173 (proxy a :3000); entra con dev-approver para firmar
```
Claves de desarrollo (solo si `NODE_ENV != production`): `dev-viewer`, `dev-analyst`, `dev-approver` (org `org_acme`) en la cabecera `x-api-key`.
En producción define `SENTINEL_API_KEYS` y `APPROVAL_SIGNING_KEY` (obligatorio).

## API REST (`/api/v1`)
| Método | Ruta | Rol |
|---|---|---|
| POST | `/scans/ingest` (`sarif`, `trivy`, `semgrep`, `zap`, `secrets`) | analyst |
| POST | `/assets` — contexto de activo para la correlación | analyst |
| GET | `/exposures/summary` · `/findings/:id/trace` (reporte → plan) | viewer |
| POST | `/iam/audit-roles` (menor privilegio; `submitForApproval`) | analyst |
| POST | `/secrets/rotate` | analyst |
| POST | `/incidents/trigger` | analyst |
| POST | `/remediations/simulate` (dry-run; `submitForApproval`) | analyst |
| GET | `/approvals` · POST `/approvals/:id/decision` | viewer · **approver** |
| GET | `/executions/:id` · `/executions/:id/forensics` · `/incidents/:id` · `/audit` | viewer |

## Criterios de aceptación del MVP
- **Trazabilidad**: `GET /findings/:id/trace` devuelve hallazgo → reporte original (hash) → planes simulados. ✔ test `traces a finding…`
- **Rotación sin cortes**: healthcheck antes de revocar; rollback si falla. ✔ tests de `zero-downtime rotation`
- **Nada en producción sin la bandeja**: adaptadores rechazan acciones sin prueba de aprobación firmada. ✔ tests de `dry-run simulation & approval gate`
- **Arquitectura + simulación**: [`docs/architecture.md`](docs/architecture.md) y `npm run simulate`.

### Suites que usan servicios reales (se saltan solas si faltan)
| Variable | Qué activa |
|---|---|
| `REDIS_URL` | cola BullMQ y lock distribuido contra Redis |
| `AWS_TEST_ENDPOINT` (p. ej. `moto_server -p 5555`) | adaptadores S3/Secrets Manager/WAFv2/IAM/EC2/KMS y flujos completos |
| `TEST_DATABASE_URL` (+ `TEST_DATABASE_ADMIN_URL`) | repositorios Postgres con dos réplicas, carreras y RLS (`db/schema.sql` + `db/roles.sql` aplicados) |
| `TF_TEST_BIN` (+ `AWS_TEST_ENDPOINT`) | `terraform plan/apply` real contra el emulador (en local sin registro: `TF_TEST_RC` con un espejo de proveedor y `TF_TEST_AWS_VERSION`) |

Producción: `INFRA_MODE=aws`, OIDC (`OIDC_ISSUER`…), firma KMS/Ed25519 y Postgres; ver [`docs/architecture.md`](docs/architecture.md).

Qué está simulado y qué falta para producción: ver la última sección de [`docs/architecture.md`](docs/architecture.md).

## Malla de servicios (mTLS, circuit breakers, trazabilidad)
Configuración de red para el ecosistema «Segundo Cerebro»: [`docs/mesh.md`](docs/mesh.md). Catálogo único `infra/mesh/services.yaml` → `npm run mesh:gen` → `infra/mesh/generated/` (Istio + NetworkPolicy); `infra/mesh/validate.sh` la valida sin clúster.

## La consola
- **Resumen**: una frase que dice dónde estás (hallazgos, credenciales expuestas, firmas pendientes) y un mapa que sitúa cada activo según esté expuesto a Internet y protegido por gateway; es lo que explica su puntuación.
- **Hallazgos**: ordenados por exposición real; cada uno muestra el desglose «severidad del escáner → ajustes por contexto → puntuación» y la cadena informe (hash) → hallazgo → plan.
- **Decisiones**: cada cambio se presenta como una orden de trabajo (qué ocurrirá, si es reversible, diferencias exactas, Terraform, estado de la ejecución, hash del plan). La firma exige **mantener pulsado** (ratón, táctil o teclado) y la barra de decisión queda fija abajo; rechazar exige motivo. Quien solicitó un cambio no puede firmarlo y el rol `viewer` ni siquiera ve el botón activo.
- **Incidentes**: resumen cuyas líneas citan la evidencia congelada (clic para resaltarla) con comprobación de integridad.
- Tests: `npm test -w apps/web` (vitest) y `npm run e2e -w apps/web` (Playwright contra la API demo: firma real con pulsación sostenida, rechazo con motivo, móvil sin desbordes). Las capturas quedan en `apps/web/shots`.
