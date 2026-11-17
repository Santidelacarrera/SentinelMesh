# Despliegue

No se despliega nada ni se generan costes sin autorización expresa: todo lo siguiente son artefactos reproducibles. **No se ha desplegado en ningún clúster real** (solo `helm lint --strict` y `helm template`).

## Artefactos
| Qué | Dónde | Verificado |
|---|---|---|
| Imágenes | `apps/api/Dockerfile`, `apps/web/Dockerfile` (nginx sin root), `services/analytics/Dockerfile` | **las 3 imágenes se construyeron y ejecutaron localmente** (API 448 MB, web 75 MB, analítica 252 MB): la API arrancó en `NODE_ENV=production` contra PostgreSQL 16, Redis 7 y un S3 emulado (moto) con logs JSON, `/readyz` OK, migraciones desde la imagen, y también con `--read-only --cap-drop ALL`; la web (nginx sin root, `--read-only`) sirvió la consola y proxeó `/api`; se inició sesión de usuario desde el navegador. **No** se escanearon con Trivy ni se desplegaron en Kubernetes |
| Docker Compose (laboratorio) | `docker-compose.yml` | sin ejecutar en esta sesión (PostgreSQL 16 y Redis 7 se levantaron con `docker run` para las pruebas) |
| Helm | `deploy/helm/sentinelmesh` | `helm lint --strict`, `helm template` |
| Migraciones | `db/migrate.js` (Job *pre-install/pre-upgrade*) | probadas en PostgreSQL 16 real en dos órdenes: migrar → roles → migrar, y roles → migrar |
| CI | `.github/workflows/{ci,security,release}.yml` | no ejecutados aquí (requieren GitHub Actions) |

> Con Docker puro y sistema de archivos de solo lectura, la web necesita `--tmpfs /etc/nginx/conf.d:uid=101,gid=101` (nginx renderiza ahí su configuración); en Kubernetes el `emptyDir` del chart ya es escribible.

## Helm
```bash
kubectl create secret generic sm-secrets --from-env-file=prod.env      # o External Secrets / Vault: el chart NUNCA incluye secretos
helm upgrade --install sm deploy/helm/sentinelmesh \
  --set secrets.existingSecret=sm-secrets --set config.OBJECT_STORE_BUCKET=mi-bucket \
  --set images.api.repository=registry/sentinelmesh-api --set ingress.enabled=true --set ingress.host=sm.mi-dominio.com --set ingress.tlsSecretName=sm-tls
```
El chart falla si falta `secrets.existingSecret`. Los pods corren sin root, con sistema de archivos de solo lectura y sin capacidades; hay `NetworkPolicy` para que solo la API hable con la analítica.

## Actualizaciones y *rollback*
- Migraciones **solo hacia delante**, transaccionales y con SHA-256. Un *rollback* de aplicación (`helm rollback`) es seguro mientras la versión anterior tolere las tablas nuevas (las migraciones son aditivas). Para revertir una migración, restaura la copia de seguridad previa.
- `helm upgrade` ejecuta primero el Job de migración; si falla, no se actualiza la aplicación.

## Copias de seguridad y recuperación (procedimiento; no automatizado aquí)
1. **PostgreSQL**: copia lógica diaria (`pg_dump`) + WAL/PITR del servicio gestionado; contiene auditoría, casos y metadatos de evidencia.
2. **Almacén de objetos**: versionado y *object lock* (WORM) en el bucket de evidencia/informes; la integridad se re-verifica por SHA-256 en cada lectura.
3. **Claves**: respalda `SECRETS_ENCRYPTION_KEY` (y las anteriores durante la rotación) por separado: sin ella no se pueden descifrar credenciales de conectores ni semillas MFA.
4. **Prueba de restauración trimestral** y comprobación de la cadena de auditoría (`GET /api/v1/audit` → `verify.ok`).
5. RPO/RTO: **no se prometen**; dependen de tu infraestructura.

## Operación
Reglas de alerta de ejemplo: `deploy/prometheus/alerts.yaml`. Logs JSON: `LOG_FORMAT=json` (por defecto en producción). `/healthz` (vida), `/readyz` (BD y cola), `/metrics` (con `METRICS_TOKEN`), `GET /api/v1/ops/health` (por organización: conectores caídos, tareas atascadas, cola, fallos de login/notificación). Trazas: se propagan `traceparent`/`x-request-id`; exportar con un *collector* OpenTelemetry delante de la malla es trabajo pendiente (`ROADMAP.md`).
