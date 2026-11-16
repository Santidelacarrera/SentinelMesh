# Auditoría inicial de SentinelMesh (Fase 1)

Fecha: 2026-11-16 · Rama de trabajo: `sentinelmesh-enterprise-upgrade` (desde `origin/main` @ `94463c8`).
Entorno de la auditoría: Windows 11, Node 22, Python 3.12, Docker CLI presente; **sin** Redis, PostgreSQL, Terraform ni moto locales (sus pruebas se omiten solas).

## 1. Estado real (ejecutado, no supuesto)
| Comprobación | Resultado |
|---|---|
| `npm ci` | OK |
| `npm run lint` (ESLint + security, 0 avisos) | OK |
| `npm run build` (API + consola) | OK |
| `npm test -w apps/api` | 88 pasan, 27 omitidas (Redis, Postgres, moto, Terraform, contrato Python) |
| `npm test -w apps/web` | 8 pasan |
| `pytest services/analytics` | 8 pasan |

## 2. Arquitectura encontrada
- **`apps/api` (NestJS 11, TypeScript)**: plano de control. Ingesta de escáneres (SARIF/Trivy/Semgrep/ZAP/secretos), correlación contextual, motor de workflows idempotente con puerta de aprobación firmada (HMAC/Ed25519/KMS), auditoría encadenada por hash, forense write-once con SHA-256, rotación de credenciales sin cortes, Terraform en dry-run, adaptadores AWS opcionales.
- **`services/analytics` (FastAPI)**: analítica determinista (puntuación de exposición, mínimo privilegio, resumen forense con citas). Tiene *fallback* idéntico en TypeScript (contrato probado).
- **`apps/web` (React + Vite)**: consola SecOps en español.
- **Datos**: PostgreSQL con documentos JSONB + columnas generadas + RLS forzada (`db/schema.sql`), o memoria.
- **Infra**: Docker Compose, malla Istio generada, Terraform de ejemplo, CI en GitHub Actions.
- **Decisión de responsabilidades** (ver ADR-0008): el prompt asume Python como backend principal; en realidad el control plane es NestJS. Los motores nuevos (CTEM, IAM, correlación, SOAR, conectores) se implementan **una sola vez en TypeScript** dentro del control plane; Python conserva su rol de analítica determinista. Así no se duplica lógica.

## 3. Matriz de brechas inicial
| Capacidad | Estado | Notas |
|---|---|---|
| Ingesta de escáneres y dedupe | IMPLEMENTADO Y VERIFICADO | pruebas e2e |
| Aprobación firmada ligada al plan, separación de funciones | IMPLEMENTADO Y VERIFICADO | |
| Motor de workflows idempotente / reanudable | IMPLEMENTADO Y VERIFICADO | |
| Auditoría encadenada por hash | IMPLEMENTADO Y VERIFICADO | Postgres real omitido localmente |
| Aislamiento por organización (repos con `orgId`, RLS) | IMPLEMENTADO PARCIALMENTE | RLS probada solo con Postgres (omitida aquí); sin gestión de organizaciones/usuarios |
| Autenticación | IMPLEMENTADO PARCIALMENTE | claves API en memoria + OIDC; sin usuarios, contraseñas, MFA, sesiones, revocación ni bloqueo por fuerza bruta |
| RBAC | IMPLEMENTADO PARCIALMENTE | 4 roles lineales; sin permisos granulares ni rol de plataforma |
| Rotación de credenciales / IAM de mínimo privilegio | IMPLEMENTADO Y VERIFICADO | solo por rol AWS puntual |
| Adaptadores AWS (Secrets, WAF, IAM, EC2, S3) | IMPLEMENTADO MEDIANTE SIMULACIÓN | probados solo contra moto (emulador) |
| Forense Prometheus/Loki/K8s | IMPLEMENTADO MEDIANTE SIMULACIÓN | dobles con la forma de las respuestas |
| Inventario de activos (tipo, propietario, relaciones, verificación) | NO IMPLEMENTADO | solo `AssetContext` con 4 booleanos |
| Gestión de vulnerabilidades (CVE/CVSS/KEV/EPSS, estados, SLA) | IMPLEMENTADO PARCIALMENTE | hallazgos de escáner sin CVE/CVSS estructurados |
| Attack Surface Management | NO IMPLEMENTADO | |
| Attack Path Analysis | NO IMPLEMENTADO | |
| Priorización CTEM contextual | IMPLEMENTADO PARCIALMENTE | puntuación por contexto de activo; sin KEV/EPSS/controles compensatorios |
| Gestión de identidades (IAM hygiene) | NO IMPLEMENTADO | solo análisis de un rol AWS |
| Conectores CrowdStrike / Defender / Wazuh / Entra / Okta / Google / Azure / GCP | NO IMPLEMENTADO | |
| Correlación multi-fuente | NO IMPLEMENTADO | |
| Gestión de incidentes (estados, línea de tiempo, comentarios) | IMPLEMENTADO PARCIALMENTE | incidentes de anomalías de tráfico únicamente |
| Evidencia con cadena de custodia | IMPLEMENTADO PARCIALMENTE | write-once + SHA-256; sin registro de accesos/exportaciones |
| SOAR: playbooks, OBSERVE/ASSISTED/AUTOMATED | IMPLEMENTADO PARCIALMENTE | workflows fijos con aprobación; sin playbooks por disparador ni niveles |
| Notificaciones Email/Slack/Teams | NO IMPLEMENTADO | `notify` es un paso simulado |
| Informes PDF | NO IMPLEMENTADO | |
| IA asistiva | NO IMPLEMENTADO | (analítica determinista con citas existe) |
| Observabilidad (logs estructurados, métricas, health) | IMPLEMENTADO PARCIALMENTE | `/healthz`, correlación de request-id; sin métricas ni readiness |
| Dashboard | IMPLEMENTADO PARCIALMENTE | 8 vistas; sin CTEM/IAM/SOAR/integraciones/ejecutiva |
| CI/CD | IMPLEMENTADO PARCIALMENTE | lint, tests, audit; sin escaneo de contenedores ni release |
| Despliegue (Compose) | IMPLEMENTADO PARCIALMENTE | Compose probado solo con `config`; sin Helm |
| Documentación exigida (19 archivos) | IMPLEMENTADO PARCIALMENTE | README, architecture.md, ADRs |

## 4. Riesgos detectados
1. `AuthService` permite claves de desarrollo si `NODE_ENV != production`: un despliegue mal configurado las habilitaría. → se exigirá configuración explícita.
2. Claves API estáticas y sin caducidad ni revocación.
3. Límite de peticiones en memoria por réplica (documentado).
4. Sin CORS explícito; la API es solo same-origin vía proxy.
5. Las pruebas de PostgreSQL/RLS no corren sin servicios: la verificación de aislamiento a nivel de BD depende de CI.
6. `next` del `MESH`/Istio: configuración generada sin clúster real validado.

## 5. Compatibilidad
No se elimina nada existente: los endpoints `/api/v1/*` actuales, los workflows y las pruebas se conservan. Los módulos nuevos se añaden como repositorios y servicios nuevos en el mismo `Db`.
