# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versión de la rama: 0.1.0 → pendiente de decisión del propietario.

## [Sin publicar] — rama `sentinelmesh-enterprise-upgrade` (madurez: ALPHA)
### Añadido
- **Seguridad de acceso**: usuarios con scrypt y política de contraseñas, bloqueo por fuerza bruta, MFA TOTP, sesiones con refresh rotativo, permisos granulares, roles propios, administración de plataforma, planes y límites.
- **CTEM**: inventario con verificación de propiedad y alcance, importación NVD/KEV/EPSS, vulnerabilidades, exposición con control de falsos positivos e historial, sonda TLS autorizada, rutas de ataque teóricas, prioridad contextual explicable.
- **IAM**: identidades humanas y de servicio, historial de privilegios, riesgos explicables, propuestas de reducción (sin aplicar).
- **Conectores**: transporte común (reintentos, límite de tasa, SSRF, renovación de token) y Wazuh, CrowdStrike, Defender, Entra, Okta, Google Workspace, AWS, Azure, GCP (probados con mocks de protocolo).
- **Señales, correlación y casos**: deduplicación, correlación con confianza por razón, casos con línea de tiempo, evidencia con cadena de custodia y exportación.
- **SOAR**: playbooks versionados, OBSERVE/ASSISTED/AUTOMATED (apagado por defecto), aprobación firmada ligada al paso, kill switch, ejecutor de laboratorio.
- **Notificaciones** (email/Slack/Teams con confirmación del proveedor), **informes PDF** (ejecutivo, técnico, incidente, identidades), **dashboard ejecutivo**, **asistente de IA** con fuentes (LLM externo opt-in), **herramientas de privacidad** (exportación, retención, borrado).
- **Operación**: `/metrics`, `/readyz`, salud por organización, CORS cerrado, límite de tasa de autenticación, HSTS, logs JSON con request-id (`LOG_FORMAT=json`), reglas de alerta Prometheus, retención programada, cuota diaria de eventos, re-cifrado tras rotar clave.
- **Rendimiento**: correlación indexada (ingesta de señales 6,6× más rápida) y dashboard sin recálculos simultáneos.
- **Consola**: vistas Ejecutiva, CTEM, IAM, SOAR, Casos, Integraciones, Informes y Administración (usuarios, roles, plan, salud); acceso con usuario/MFA y renovación de sesión.
- **Datos**: migración `0002_enterprise` (27 tablas con RLS), runner versionado `db/migrate.js`.
- **Entrega**: workflows `security.yml` y `release.yml`, imagen web, chart de Helm, `.env.example`, demo reproducible (`npm run demo:enterprise`), sonda de rendimiento.
- Documentación: `docs/` (arquitectura, amenazas, API, instalación, despliegue, guías, comercial, competitivo, hoja de ruta).
### Corregido durante la verificación
- Varias señales del mismo host abrían una aprobación por alerta: ahora se agrupan en la ejecución que espera aprobación.
- La lista de evidencia de un caso ajeno devolvía `200 []`; ahora `404`.
### Cambiado
- `AuthService` ya no es solo claves API; el rol `platform_admin` se añade a la jerarquía. Producción exige `SECRETS_ENCRYPTION_KEY`.
- Acceso a filas de otra organización en `update()` devuelve 404 (antes 500).
### Compatibilidad
Los endpoints, flujos y pruebas del núcleo anterior se conservan.
