# Hoja de ruta y bloqueos

## Madurez actual: **ALPHA**
El núcleo y los módulos empresariales funcionan y tienen pruebas reproducibles (incluida PostgreSQL real), pero faltan integraciones verificadas con servicios reales, validación operativa y varios componentes de producción.

## Bloqueos externos (no se pueden cerrar sin tu intervención)
| Bloqueo | Qué falta | Cómo desbloquearlo |
|---|---|---|
| Conectores reales | credenciales de solo lectura de AWS/Azure/GCP/CrowdStrike/Defender/Wazuh/Entra/Okta/Google | `CONNECTORS.md` → «Cómo validar» |
| CI en GitHub Actions | los workflows nuevos no se han ejecutado | abrir PR y revisar las ejecuciones (construcción y escaneo de imágenes, Trivy, gitleaks) |
| Moto/Terraform | 21 pruebas del núcleo previo siguen omitidas localmente (emulador AWS, Terraform, contrato con Python) | ejecutar en CI o instalar `moto_server` y Terraform |
| Despliegue en clúster | Helm solo validado sintácticamente | clúster de pruebas autorizado |
| Licencia del repositorio | sin asignar | decisión del propietario |
| Revisión humana | nada se ha fusionado ni empujado | revisar la rama `sentinelmesh-enterprise-upgrade` |

## Próximos pasos concretos (por prioridad)
1. **Validar conectores** contra tenants de prueba y corregir las diferencias de campos.
2. **Rendimiento** (ver `TESTING.md`): la correlación y los listados recorren toda la organización en memoria (O(n)); mover filtros y orden a SQL (columnas generadas/índices), indexar señales por activo/IP y acotar la ventana de búsqueda. Re-medir con PostgreSQL.
3. **Ejecutores reales** con permisos de escritura separados, autorización adicional y *rollback* por acción (bloqueo de cuenta, revocación de sesiones, aislamiento EDR), siempre tras la aprobación firmada.
4. **Observabilidad**: exportación OpenTelemetry de trazas (hoy solo propagación de `traceparent`), alertas operativas en Prometheus/Alertmanager, panel Grafana.
5. **SSO/SAML** y SCIM; aplicar `@Feature('sso')`; MFA obligatorio por política de organización; códigos de recuperación.
6. **UI**: administración de plataforma, gestión de usuarios/roles, edición de playbooks, rutas de ataque como grafo, accesibilidad auditada (WCAG), pruebas Playwright de las vistas nuevas.
7. **Cumplimiento**: mapa de controles (NIST CSF/CIS/ISO 27001 → funciones del producto), política de retención de auditoría con exportación firmada, DPIA plantilla.
8. **Licenciamiento y facturación** (ver `COMMERCIAL_MODEL.md`), aplicar `eventsPerDay`.
9. **Active Directory local** (LDAP) o guía oficial de Entra Connect.
10. Cache y paginación en SQL para vulnerabilidades/señales; *job* de retención programado; rotación automática de `SECRETS_ENCRYPTION_KEY` (re-cifrado).

## Riesgos que impiden producción hoy
Conectores sin verificar · sin ejecutores reales (SOAR solo laboratorio) · rendimiento sin medir sobre PostgreSQL ni a escala · sin pentest independiente ni certificaciones · imágenes y Helm sin desplegar · claves API estáticas aún soportadas · límite de tasa por réplica · sin plan de backup automatizado.
