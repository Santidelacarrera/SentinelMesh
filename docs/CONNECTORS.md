# Conectores

## Estado honesto (léelo primero)
| Clasificación | Significado |
|---|---|
| **simulado** | apunta a un endpoint local/de pruebas |
| **implementado** | el código existe y está probado contra un servidor local que habla el protocolo documentado; **no verificado contra un servicio real** |
| **conectado** | una prueba de conexión **real** (host no local) tuvo éxito; lo calcula el sistema, nunca se declara a mano |
| **no implementado** | Active Directory local (LDAP): usa Entra Connect + el conector Entra |

**Hoy ningún conector está "verificado con servicio real"**: las pruebas (`apps/api/test/connectors.spec.ts`) usan servidores HTTP locales construidos a partir de la documentación pública de cada producto. Pueden existir diferencias con la API real (campos, paginación, límites). Validación pendiente de tus credenciales: ver «Cómo validar».

## Catálogo y permisos mínimos (solo lectura)
| Conector | Autenticación | Datos | Permisos que pide |
|---|---|---|---|
| Wazuh | JWT de `/security/user/authenticate` (renovado antes de caducar) | agentes → activos; alertas y vulnerabilidades desde el *indexer* (`options.indexerUrl`) | rol de API con `agent:read`, `manager:read`; usuario del indexer con lectura en `wazuh-alerts-*` y `wazuh-states-vulnerabilities-*` |
| CrowdStrike Falcon | OAuth2 client credentials | hosts → activos; alertas v2 → señales | scopes *Hosts: Read*, *Alerts: Read* |
| Microsoft Defender | OAuth2 (un token por audiencia: Graph y Defender for Endpoint) | alertas_v2, máquinas, vulnerabilidades por máquina | Graph `SecurityAlert.Read.All`, `SecurityIncident.Read.All`; MDE `Machine.Read.All`, `Vulnerability.Read.All` |
| Microsoft Entra ID | OAuth2 (Graph) | usuarios, roles de directorio, registro MFA, último inicio de sesión | `User.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All` |
| Okta | token SSWS | usuarios, factores MFA, roles de administrador | token de administrador de solo lectura |
| Google Workspace | cuenta de servicio con delegación de dominio (JWT bearer) | usuarios, admin, 2SV, último acceso | `admin.directory.user.readonly` |
| AWS | SDK oficial con credenciales de solo lectura | EC2, buckets S3 (público o no), usuarios IAM (MFA, antigüedad de claves, políticas) | `SecurityAudit` / `ViewOnlyAccess` |
| Azure | OAuth2 (ARM) | VM, IP públicas, cuentas de almacenamiento | rol *Reader* (+ *Security Reader*) en la suscripción |
| GCP | cuenta de servicio (JWT) | instancias (Cloud Asset), hallazgos SCC opcionales | `roles/cloudasset.viewer` (+ `securitycenter.findingsViewer`) |

Ningún conector **escribe** en sistemas externos. Cualquier acción de respuesta real exigiría un ejecutor nuevo con autorización adicional (`ROADMAP.md`).

## Requisitos comunes (todos implementados)
Estado (`not_configured → configured → connected | syncing | error | disabled`) · última sincronización y último error (sin secretos) · caducidad de credenciales (aviso a <14 días) · registro de actividad · prueba de conectividad · reintentos acotados con *backoff* y `Retry-After` · límite de peticiones (token bucket, `options.rps`) · bloqueo para no sincronizar dos veces a la vez · activación/desactivación individual · credenciales cifradas con AES-GCM · protección SSRF por salto.

## Cómo validar un conector con un entorno real
1. Crea la credencial de solo lectura con los permisos de la tabla.
2. `POST /api/v1/connectors {kind, name, baseUrl, credentials}` (rol admin).
3. `POST /api/v1/connectors/{id}/test`: si el host no es local y funciona, la verificación pasa a **conectado**.
4. `POST /api/v1/connectors/{id}/sync` y compara activos/identidades/alertas con la consola del proveedor.
5. Anota discrepancias de campos: el normalizador está en `apps/api/src/connectors/{edr,idp,cloud}.ts`.

Para endpoints privados (Wazuh on-prem) el operador debe permitirlos: `CONNECTOR_PRIVATE_HOSTS='["wazuh.corp.local"]'` y, solo en laboratorio, `CONNECTOR_ALLOW_HTTP=1`.
