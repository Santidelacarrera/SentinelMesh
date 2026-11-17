# Seguridad de SentinelMesh

## Notificar una vulnerabilidad
No abras un issue público. Escribe en privado al propietario del repositorio (Nexus Security & AI Lab) con pasos de reproducción y versión. Se acusa recibo y se corrige antes de divulgar. No se ofrece un SLA contractual todavía.

## Controles implementados (y dónde se prueban)
| Área | Control | Prueba |
|---|---|---|
| Contraseñas | scrypt (N=16384), política (≥12, deny-list, sin reutilizar las 5 últimas), nunca en claro | `auth.spec.ts` |
| Fuerza bruta | bloqueo de cuenta tras 5 fallos (15 min), mismo coste con cuenta inexistente, límite por IP en `/auth/*`, sin enumeración de usuarios | `auth.spec.ts`, `platform.spec.ts` |
| MFA | TOTP RFC 6238 con ventana ±1 y protección contra reutilización; semilla cifrada (AES-256-GCM) | `auth.spec.ts` |
| Sesiones | token opaco con hash en BD, caducidad 15 min, refresh rotativo con detección de reutilización (revoca la familia), límite de sesiones concurrentes, revocación por administrador | `auth.spec.ts` |
| Autorización | permisos granulares + roles propios (solo aditivos), separación de funciones (quien solicita no aprueba; nadie cambia su propio rol), `platform_admin` solo en la organización de plataforma | `auth.spec.ts`, `soar.spec.ts` |
| Multi-tenant | `orgId` obligatorio en repositorios + RLS forzada en PostgreSQL | `security.spec.ts`, `pg-enterprise.spec.ts` (BD real) |
| Entrada | zod estricto en cada endpoint, límite de cuerpo 10 MB, sin asignación masiva ni contaminación de prototipos | `security.spec.ts` |
| SSRF | todo destino saliente (conectores, webhooks, IA, analítica) pasa por `assertSafeUrl`; los hosts privados solo se permiten por configuración del operador | `connectors.spec.ts`, `notifications.spec.ts` |
| Secretos | sellados con AES-256-GCM y rotación de clave (`SECRETS_ENCRYPTION_KEY[_PREVIOUS]`); nunca devueltos, registrados ni exportados; redacción previa a auditoría, informes, notificaciones e IA | `connectors.spec.ts`, `platform.spec.ts` |
| Auditoría | cadena SHA-256 por organización, append-only en BD (trigger), verificable (`GET /audit`) | `soar.spec.ts`, `security.spec.ts` |
| Evidencia | escritura única, hash verificado en cada lectura/exportación, custodia de accesos, sin API de borrado, triggers en BD | `cases.spec.ts`, `pg-enterprise.spec.ts` |
| SOAR | AUTOMATED apagado por defecto, lista blanca, presupuesto horario, riesgo alto siempre con aprobación, kill switch, aprobación ligada al hash del paso | `soar.spec.ts` |
| Cabeceras | `nosniff`, `X-Frame-Options`, CSP restrictiva, `no-store`, HSTS tras TLS; CORS cerrado salvo `CORS_ORIGINS` | `security.spec.ts` |
| Contenedores | usuario no root, `readOnlyRootFilesystem`, sin capacidades, `seccomp RuntimeDefault` (Helm) | `helm lint --strict` |
| Cadena de suministro | `npm audit`, gitleaks, Trivy (imágenes e IaC) en CI | `.github/workflows/security.yml` |

## Lo que NO está hecho / no se afirma
- No hay certificación ISO 27001, SOC 2 ni cumplimiento legal completo; las herramientas de privacidad facilitan, no certifican.
- No hay pentest independiente. Las pruebas de seguridad son automáticas y locales.
- Los conectores no se han validado contra servicios reales; ver `CONNECTORS.md`.
- Las claves API estáticas siguen soportadas por compatibilidad (`AUTH_ALLOW_API_KEYS=0` las desactiva) y `NODE_ENV!=production` registra claves de desarrollo.
- TLS lo termina el Ingress/proxy: la aplicación no sirve TLS por sí misma.
- Copias de seguridad y recuperación ante desastres: ver `DEPLOYMENT.md` (procedimiento, no automatizado aquí).
