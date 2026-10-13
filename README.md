# SentinelMesh — Nexus Security & AI Lab

Plataforma híbrida **CTEM + higiene IAM + SOAR** con orquestación y **aprobación humana** obligatoria para toda acción destructiva.
Producto de **Nexus Security & AI Lab**. Costo de ejecución y de desarrollo: **$0** (todo software libre; sin APIs de pago ni credenciales reales).

Descubre la debilidad (vulnerabilidad o llave expuesta) → evalúa el riesgo real con contexto de aplicación → recolecta evidencia forense →
simula el cambio (diff / Terraform) → ejecuta de forma idempotente **solo tras la firma de un analista SecOps**.

> **Núcleo vs. componentes opcionales.** El *núcleo* (ingesta → correlación → plan → aprobación firmada → ejecución → auditoría, rotación sin cortes e incidentes con evidencia)
> funciona y se prueba **sin red ni nube**: los puertos externos son simulaciones en proceso por defecto ([ADR-0001](docs/adr/0001-nucleo-minimo-y-puertos-simulados.md)).
> Los adaptadores de nube (AWS) son opcionales (`INFRA_MODE=aws`). Decisiones y bitácora: [`docs/BITACORA.md`](docs/BITACORA.md).

## Requisitos
Node.js ≥ 22.22 y npm ≥ 10 · Python ≥ 3.12 (probado con 3.13) · (opcional) Redis, PostgreSQL 16 y Docker para las suites de integración. Nada más: no hace falta cuenta de nube.

| Capa | Tecnología | Ruta |
|---|---|---|
| API / control plane + motor | NestJS, BullMQ/Redis | `apps/api` |
| Consola SecOps (resumen y mapa de exposición, hallazgos con su porqué, decisiones con firma, ejecuciones, incidentes, identidades, credenciales, auditoría) | React + TypeScript (Vite) | `apps/web` |
| Analítica y contexto | Python + FastAPI | `services/analytics` |
| Datos | PostgreSQL (`db/schema.sql`, RLS), S3/MinIO (contrato `ObjectStorage`) | `db/` |
| Infra | Docker Compose, Terraform de ejemplo | `docker-compose.yml`, `infra/` |

## Instalar y probar (reproducible, sin servicios externos)
```bash
git clone <este-repositorio> && cd SentinelMesh
npm ci                                  # dependencias Node (0 vulnerabilidades: ver «Calidad y seguridad»)
npm test                                # API (unitarios + e2e HTTP del núcleo) + consola (vitest)  → 0 fallos
npm run simulate                        # incidente controlado completo: el aprobador APRUEBA
npm run simulate -- --reject            # el aprobador RECHAZA: no cambia nada
python3 -m venv .venv && . .venv/bin/activate
pip install -r services/analytics/requirements-dev.txt
pytest -q services/analytics            # servicio de analítica
```
`npm run simulate` ingesta un SARIF y una fuga de credencial, rota la llave con healthcheck (la antigua sigue válida mientras espera),
dispara un brute-force, congela la evidencia, muestra la bandeja con los diffs y aplica/rechaza. Termina con la cadena de auditoría verificada.

### Pruebas de integración (opcionales: Redis, Postgres, emulador de AWS, contrato con Python)
Se saltan solas si falta la variable. Con todo activado la API pasa **99 pruebas** (cobertura: líneas 98 %, sentencias 94 %; `npm run test:coverage -w apps/api`).
```bash
docker compose up -d redis postgres                       # o servicios locales; db/schema.sql y db/roles.sql se aplican al arrancar postgres
python3 -m venv /tmp/moto && /tmp/moto/bin/pip install "moto[server,s3,secretsmanager,wafv2,iam,kms,ec2]" && /tmp/moto/bin/moto_server -p 5555 &
(cd services/analytics && uvicorn app.main:app --port 8099 &)
export REDIS_URL=redis://localhost:6379 AWS_TEST_ENDPOINT=http://localhost:5555 ANALYTICS_TEST_URL=http://127.0.0.1:8099
export TEST_DATABASE_URL=postgres://sentinel_app:dev-only-app@localhost:5432/sentinelmesh TEST_DATABASE_ADMIN_URL=postgres://postgres:dev-only@localhost:5432/sentinelmesh
npm test -w apps/api
```
| Variable | Qué activa |
|---|---|
| `REDIS_URL` | cola BullMQ y bloqueo distribuido contra Redis |
| `AWS_TEST_ENDPOINT` | adaptadores S3/Secrets Manager/WAFv2/IAM/EC2/KMS y flujos completos contra un emulador |
| `TEST_DATABASE_URL` (+ `_ADMIN_URL`) | persistencia PostgreSQL y RLS |
| `ANALYTICS_TEST_URL` | contrato: el servicio Python y el fallback local dan respuestas idénticas |
| *(Playwright)* `npm run e2e -w apps/web` | consola en un navegador real contra la API demo |

## Calidad y seguridad
```bash
npm run lint            # ESLint + eslint-plugin-security + react-hooks, 0 avisos permitidos
npm run audit:deps      # npm audit --audit-level=high (incluye dependencias de desarrollo)
npm run build           # compila API y consola
npm run check           # lint + tests + build
ruff check services/analytics && ruff format --check services/analytics && bandit -q -r services/analytics/app -ll
```
Todo esto se ejecuta también en CI (`.github/workflows/ci.yml`). Semgrep no se ejecuta en este entorno (registro de reglas inaccesible): ver pendientes.

## Usar
```bash
npm run dev -w apps/api        # API en :3000 sin Docker (cola en memoria, servicios simulados)
docker compose up --build      # alternativa: api :3000, redis, postgres, minio, analytics
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

## Definición de terminado: evidencia por criterio
| Criterio del MVP | Evidencia (prueba) |
|---|---|
| Alerta trazable desde su informe hasta el plan simulado | `traces a finding from report to simulated plan` |
| Rotación sin cortes (healthcheck antes de revocar; rollback si falla) | `zero-downtime rotation` (3 pruebas) |
| Nada destructivo sin firma en la bandeja SecOps | `dry-run simulation & approval gate` (5 pruebas), `forged approvals cannot unlock adapters` |
| Resiliencia del motor (caída de worker, reanudación, reintentos, carrera) | `engine resilience` (4 pruebas) |
| Aislamiento por organización y enmascarado de secretos | `isolates organisations`, `masks leaked secrets everywhere…` |
| Arquitectura documentada + simulación de incidentes | [`docs/architecture.md`](docs/architecture.md), [`docs/adr/`](docs/adr), `npm run simulate` |

Detalle de cada uno:

- **Trazabilidad**: `GET /findings/:id/trace` devuelve hallazgo → reporte original (hash) → planes simulados. ✔ test `traces a finding…`
- **Rotación sin cortes**: healthcheck antes de revocar; rollback si falla. ✔ tests de `zero-downtime rotation`
- **Nada en producción sin la bandeja**: adaptadores rechazan acciones sin prueba de aprobación firmada. ✔ tests de `dry-run simulation & approval gate`
- **Arquitectura + simulación**: [`docs/architecture.md`](docs/architecture.md) y `npm run simulate`.

Producción: `INFRA_MODE=aws`, OIDC (`OIDC_ISSUER`…), firma KMS/Ed25519 y Postgres; ver [`docs/architecture.md`](docs/architecture.md).

Qué está simulado y qué falta para producción: ver la última sección de [`docs/architecture.md`](docs/architecture.md).

## La consola
- **Resumen**: una frase que dice dónde estás (hallazgos, credenciales expuestas, firmas pendientes) y un mapa que sitúa cada activo según esté expuesto a Internet y protegido por gateway; es lo que explica su puntuación.
- **Hallazgos**: ordenados por exposición real; cada uno muestra el desglose «severidad del escáner → ajustes por contexto → puntuación» y la cadena informe (hash) → hallazgo → plan.
- **Decisiones**: cada cambio se presenta como una orden de trabajo (qué ocurrirá, si es reversible, diferencias exactas, Terraform, estado de la ejecución, hash del plan). La firma exige **mantener pulsado** (ratón, táctil o teclado) y la barra de decisión queda fija abajo; rechazar exige motivo. Quien solicitó un cambio no puede firmarlo y el rol `viewer` ni siquiera ve el botón activo.
- **Incidentes**: resumen cuyas líneas citan la evidencia congelada (clic para resaltarla) con comprobación de integridad.
- Tests: `npm test -w apps/web` (vitest) y `npm run e2e -w apps/web` (Playwright contra la API demo: firma real con pulsación sostenida, rechazo con motivo, móvil sin desbordes). Las capturas quedan en `apps/web/shots`.

## Componentes reutilizables (sin acoplar a ningún cliente)
Pensados para reutilizarse en otros productos de Nexus Security & AI Lab, copiando el código sin datos ni credenciales: enmascarado de secretos (`apps/api/src/common/mask.ts`),
defensa SSRF (`common/ssrf.ts`), traza de auditoría encadenada (`audit/audit-trail.ts`), firma de aprobaciones con varios backends (`approvals/signer.ts`),
motor de flujos idempotente con puerta de aprobación (`workflow/`), validación estricta de entradas (`common/zod.ts`).

## Licencia y gobernanza
Propiedad de Nexus Security & AI Lab (Santiago). Los cambios requieren aprobación humana antes de fusionarse.
