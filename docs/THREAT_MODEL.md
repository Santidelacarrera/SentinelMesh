# Modelo de amenazas (STRIDE resumido)

SentinelMesh concentra credenciales de integración, evidencia y poder de respuesta: es un objetivo de alto valor.

## Activos a proteger
Credenciales de conectores · semillas MFA y hashes de contraseña · evidencia forense · cadena de auditoría · capacidad de aprobar/ejecutar acciones · datos de cada organización.

## Fronteras de confianza
Internet → Ingress (TLS) → web/API → PostgreSQL/Redis/almacén de objetos · API → conectores (salida) · API → IA externa (opt-in) · Administradores de plataforma ↔ organizaciones.

## Amenazas y mitigaciones
| # | Amenaza | Mitigación | Riesgo residual |
|---|---|---|---|
| S1 | Robo/relleno de credenciales | scrypt, bloqueo, límite por IP, MFA, no enumeración | Sin detección de contraseñas filtradas externas |
| S2 | Robo de token de sesión | caducidad corta, refresh rotativo con detección de reutilización, revocación | Un token robado vale hasta 15 min |
| S3 | Suplantar a otro tenant forjando el token | el tenant sale de la sesión almacenada, no del token; `x-tenant` debe coincidir | — |
| T1 | Alterar una acción aprobada | la aprobación firma el hash del paso exacto; se re-verifica al ejecutar | La clave de firma es un secreto crítico (usar KMS) |
| T2 | Alterar evidencia/auditoría | write-once + SHA-256 + custodia; cadena de hashes; triggers en BD | Un DBA con rol propietario puede alterar la BD (mitigar con réplica/WORM externo) |
| R1 | Repudio de acciones | auditoría por actor y request-id, aprobaciones firmadas | — |
| I1 | Fuga entre tenants (BOLA) | repos con `orgId` + RLS forzada; 404 uniforme; barridos en `security.spec.ts` | Código nuevo que olvide `orgId` (mitigado por el tipo `Repo`) |
| I2 | Fuga de secretos en logs/informes/IA | redacción central, AES-GCM, exclusión en exportaciones, pseudonimización para IA | Redacción heurística: patrones nuevos pueden escapar |
| I3 | SSRF vía webhooks/conectores | `assertSafeUrl` en cada salto, listas explícitas | DNS rebinding parcial (se resuelve antes de conectar) |
| D1 | Tormenta de alertas / inundación | límite de tasa, control de tormenta en notificaciones, deduplicación | Límite por réplica, no global |
| D2 | Automatización fuera de control | AUTOMATED off, lista blanca, presupuesto, kill switch | — |
| E1 | Escalada de privilegios | permisos aditivos, `platform_admin` aislado, separación de funciones | Un `admin` de organización es todopoderoso dentro de ella |
| E2 | La IA ejecuta acciones o filtra datos | sin ruta de escritura; solo narrativa, con consentimiento + operador + pseudonimización | El proveedor externo recibe texto pseudonimizado |
| X1 | Conector malicioso devuelve datos hostiles | validación y normalización, redacción de `raw`, sin ejecución de contenido | Datos falsos pueden generar ruido/casos |

## Fuera de alcance
Compromiso del host/Kubernetes, del proveedor cloud, del IdP, o de la cadena de compilación del operador.
