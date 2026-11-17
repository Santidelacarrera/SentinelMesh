# Instalación (laboratorio reproducible)

## Requisitos
| Recurso | Laboratorio (1 usuario, datos de prueba) | Mínimo sugerido para un piloto* |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU (API 2 réplicas × 1 vCPU + PostgreSQL) |
| Memoria | 4 GB | 8 GB (la API pidió ~1 GB de heap con 500 vulnerabilidades y 2 000 señales en memoria, ver `TESTING.md`) |
| Disco | 2 GB | 20 GB + crecimiento de evidencia/informes en el almacén de objetos |
| Red | solo local | salida HTTPS a los conectores que actives; entrada 443 |
| Software | Node ≥ 22.22, Python ≥ 3.12 | + PostgreSQL 16, Redis 7, almacén S3/MinIO |

\* Orientativo: no es una medición de capacidad. Dimensiona con tu propia prueba (`npm run perf -w apps/api`).

## 1. Solo local, sin servicios externos (memoria, puertos simulados)
```bash
git clone https://github.com/Santidelacarrera/SentinelMesh.git && cd SentinelMesh
npm ci
npm test                       # unitarias + e2e en memoria
npm run demo:enterprise -w apps/api   # escenario completo de 12 pasos con fuente SIMULADA y ejecutor de laboratorio
npm run demo                   # API con datos de ejemplo en :3000 (claves dev-viewer / dev-analyst / dev-approver)
npm run dev -w apps/web        # consola en :5173
```

## 2. Con PostgreSQL y Redis reales (Docker)
```bash
docker compose up -d redis postgres          # aplica db/schema.sql, db/roles.sql y la migración 0002 al crear la BD
export DATABASE_ADMIN_URL=postgres://postgres:dev-only@localhost:5432/sentinelmesh
npm run db:migrate -w apps/api               # idempotente; registra cada migración con su SHA-256
export TEST_DATABASE_URL=postgres://sentinel_app:dev-only-app@localhost:5432/sentinelmesh TEST_DATABASE_ADMIN_URL=$DATABASE_ADMIN_URL REDIS_URL=redis://localhost:6379
npm test -w apps/api                         # ahora también ejecuta RLS, inmutabilidad y bloqueos reales
```

## 3. Primer arranque (producción o piloto)
1. Copia `.env.example` → secretos reales (`SECRETS_ENCRYPTION_KEY`: `openssl rand -base64 32`; clave de firma de aprobaciones; `PLATFORM_ADMIN_*`).
2. `NODE_ENV=production` exige `INFRA_MODE=aws`, `DATABASE_URL`, `REDIS_URL`, `OBJECT_STORE_BUCKET` y `SECRETS_ENCRYPTION_KEY`; sin ellos la aplicación no arranca.
3. Migra: `DATABASE_ADMIN_URL=… node db/migrate.js` (o el *hook* de Helm).
4. Inicia sesión como administrador de plataforma y crea organizaciones: `POST /api/v1/platform/orgs`.
5. Pon `AUTH_ALLOW_API_KEYS=0` cuando ya uses sesiones/OIDC.

## Qué debe aportar el administrador (sin incluir secretos en el repositorio)
Contraseña de plataforma · clave de cifrado · clave de firma de aprobaciones (KMS/Ed25519/HMAC) · cadenas de conexión de PostgreSQL/Redis · bucket de evidencia · SMTP (si usas email) · credenciales de **solo lectura** de cada conector (ver `CONNECTORS.md`) · TLS en el Ingress.
