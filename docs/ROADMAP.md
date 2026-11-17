# Hoja de ruta y bloqueos

## Madurez actual: **ALPHA**
El núcleo y los módulos empresariales funcionan y tienen pruebas reproducibles (incluida PostgreSQL real), pero faltan integraciones verificadas con servicios reales, validación operativa y varios componentes de producción.

## Bloqueos externos (no se pueden cerrar sin tu intervención)
| Bloqueo | Qué falta | Cómo desbloquearlo |
|---|---|---|
| Conectores reales | credenciales de solo lectura de AWS/Azure/GCP/CrowdStrike/Defender/Wazuh/Entra/Okta/Google | `CONNECTORS.md` → «Cómo validar» |
| CI en GitHub Actions | los workflows nuevos no se han ejecutado | abrir PR y revisar las ejecuciones (construcción y escaneo de imágenes, Trivy, gitleaks) |
| Terraform | 4 pruebas del núcleo previo omitidas (necesitan el binario de Terraform; moto y el contrato Python ya se ejecutaron) | instalar Terraform o ejecutar en CI |
| Despliegue en clúster / Trivy | las imágenes se construyen y ejecutan en Docker local (sin escaneo Trivy); el Helm solo se validó sintácticamente | clúster de pruebas autorizado y CI |
| Licencia del repositorio | sin asignar | decisión del propietario |
| Revisión humana | nada se ha fusionado ni empujado | revisar la rama `sentinelmesh-enterprise-upgrade` |

## Próximos pasos concretos (por prioridad)
1. **Validar conectores** contra tenants de prueba y corregir las diferencias de campos.
2. **Rendimiento** (ver `TESTING.md`): la correlación ya está indexada (6,6× más rápida) y el dashboard coalescido; **siguen** los listados que filtran toda la organización en el proceso: mover filtros, orden y paginación a SQL (columnas generadas/índices) y re-medir con PostgreSQL.
3. **Ejecutores reales** con permisos de escritura separados, autorización adicional y *rollback* por acción (bloqueo de cuenta, revocación de sesiones, aislamiento EDR), siempre tras la aprobación firmada.
4. **Observabilidad**: exportación OpenTelemetry de trazas (hoy solo propagación de `traceparent`; ya hay logs JSON con request-id y reglas de alerta en `deploy/prometheus/alerts.yaml`, sin probar contra un Prometheus real), panel Grafana.
5. **SSO/SAML** y SCIM; aplicar `@Feature('sso')`; MFA obligatorio por política de organización; códigos de recuperación.
6. **UI**: administración de plataforma (organizaciones; la de usuarios/roles/plan de una organización ya existe), edición de playbooks, rutas de ataque como grafo, accesibilidad auditada (WCAG), pruebas Playwright de las vistas nuevas.
7. **Cumplimiento**: mapa de controles (NIST CSF/CIS/ISO 27001 → funciones del producto), política de retención de auditoría con exportación firmada, DPIA plantilla.
8. **Licenciamiento y facturación** (ver `COMMERCIAL_MODEL.md`); `eventsPerDay` ya se aplica por réplica (límite blando), falta un contador compartido.
9. **Active Directory local** (LDAP) o guía oficial de Entra Connect.
10. Paginación en SQL para vulnerabilidades/señales; la retención programada (`RETENTION_JOB_INTERVAL_SEC`) y el re-cifrado tras rotar clave (`POST /connectors/reencrypt`) ya existen, falta automatizar la rotación de la clave.

## Riesgos que impiden producción hoy
Conectores sin verificar · sin ejecutores reales (SOAR solo laboratorio) · rendimiento sin medir sobre PostgreSQL ni a escala · sin pentest independiente ni certificaciones · imágenes sin escanear y Helm sin desplegar · claves API estáticas aún soportadas · límite de tasa por réplica · sin plan de backup automatizado.
