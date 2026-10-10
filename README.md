# SentinelMesh

Plataforma híbrida **CTEM + higiene IAM + SOAR** con orquestación y **aprobación humana** obligatoria para toda acción destructiva.

Descubre la debilidad (vulnerabilidad o llave expuesta) → evalúa el riesgo real con contexto de aplicación → recolecta evidencia forense →
simula el cambio (diff / Terraform) → ejecuta de forma idempotente **solo tras la firma de un analista SecOps**.

| Capa | Tecnología | Ruta |
|---|---|---|
| API / control plane + motor | NestJS, BullMQ/Redis | `apps/api` |
| Panel (exposición, bandeja, forense, IAM) | React + TypeScript (Vite) | `apps/web` |
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
npm run dev -w apps/web        # panel en :5173 (proxy a :3000)
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
| `TEST_DATABASE_URL` (+ `TEST_DATABASE_ADMIN_URL`) | persistencia Postgres y RLS (`db/schema.sql` + `db/roles.sql` aplicados) |

Producción: `INFRA_MODE=aws`, OIDC (`OIDC_ISSUER`…), firma KMS/Ed25519 y Postgres; ver [`docs/architecture.md`](docs/architecture.md).

Qué está simulado y qué falta para producción: ver la última sección de [`docs/architecture.md`](docs/architecture.md).
