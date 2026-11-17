# Modelo comercial y SaaS (propuesta técnica, no oferta)

> **No hay precios de mercado ni compromisos de disponibilidad en este documento.** Las cifras de límites del código (`platform/entitlements.ts`) son **marcadores ilustrativos** para probar el mecanismo de licenciamiento; los precios y SLA los fija el negocio con asesoramiento comercial y legal.

## Planes (qué hay implementado y qué no)
| | STARTER | BUSINESS | ENTERPRISE |
|---|---|---|---|
| Descubrimiento básico, inventario | ✔ | ✔ | ✔ |
| Gestión de vulnerabilidades (NVD/KEV/EPSS importados), dashboard, informes PDF | ✔ | ✔ | ✔ |
| CTEM avanzado (exposición, rutas de ataque, comprobaciones TLS) | — | ✔ | ✔ |
| IAM (identidades, riesgos) | — | ✔ | ✔ |
| Conectores, casos/correlación/evidencia, notificaciones, IA asistiva | — | ✔ | ✔ |
| SOAR (playbooks, aprobaciones, kill switch) | — | — | ✔ |
| Roles propios, herramientas de privacidad, auditoría avanzada | — | — | ✔ |
| SSO (OIDC) | — | — | ✔ *(el soporte OIDC existe en el código; la restricción por plan solo se aplica a las vistas gestionadas por `@Feature`)* |
| Despliegue dedicado | — | — | bajo contrato (Helm incluido; operación no incluida) |

Límites ilustrativos por plan: activos, usuarios, conectores, eventos/día (`PLAN_LIMITS`). Superarlos devuelve `402` (`assertWithin`).

## Arquitectura propuesta
| Pieza | Estado |
|---|---|
| **Control de funciones por plan** | **Implementado**: `Entitlements` + `@Feature` en cada controlador; plan por organización (`org_profile`), cambio por administrador de plataforma |
| **Límites de uso** | **Parcial**: activos, usuarios y conectores se comprueban al crear; `eventsPerDay` se aplica a la ingesta de señales con un contador **por réplica** (límite blando) |
| Licenciamiento (claves firmadas, caducidad, modo sin conexión) | Propuesta: licencia JWT firmada por el proveedor con `plan`, `limits`, `exp`; verificación local; sin llamada de salida obligatoria para instalaciones dedicadas |
| Suscripciones y renovaciones | Propuesta: pasarela de pago externa (Stripe u otra) fuera del producto; webhook → `PATCH /platform/orgs/{id}` (plan, estado). **No implementado; no se integra ningún pago** |
| Facturación por uso | Propuesta: contador de eventos (señales) y activos por organización exportado mensualmente (`/privacy/export`-style, solo agregados). **No implementado** |
| Suspensión por impago | **Implementado** el mecanismo: `status: suspended` revoca sesiones y bloquea (sin borrar datos) |

## Métricas de precio a evaluar (no a fijar aquí)
Activos gestionados · endpoints · organizaciones (para MSSP) · volumen de eventos · módulos (CTEM/IAM/SOAR) · conectores · funciones avanzadas. Recomendación técnica: cobrar por **activos + módulos** y poner topes blandos de eventos; el modelo por organización encaja con MSSP.

## Riesgos comerciales/técnicos antes de vender
Sin validación con clientes reales · conectores sin verificar contra servicios reales · sin certificaciones (SOC 2/ISO 27001 requieren auditoría independiente) · sin SLA operativo · soporte y respuesta a incidentes del propio servicio por definir.
