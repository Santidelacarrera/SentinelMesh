# Guía IAM

Dos cosas distintas:
1. **Seguridad de acceso de SentinelMesh** (usuarios, MFA, sesiones, RBAC): `SECURITY.md` y `MULTITENANCY.md`.
2. **Higiene de identidades de la organización cliente** (este documento): inventario, privilegios, inactividad y riesgos.

## Identidades
`POST /iam/identities` (o conectores Entra/Okta/Google/AWS). Humanas y de servicio; proveedor + `externalId` es único. `privileged` se deduce de las *entitlements* (`*`, `iam:*`, `AdministratorAccess`, `Global Administrator`, `Domain Admins`, `cluster-admin`, `roles/owner`…; lista en `iam/iam.service.ts`) salvo que el origen lo indique.

Cada cambio de privilegios, estado o MFA se escribe en un **historial append-only** (`/iam/changes`) y en la auditoría.

## Riesgos (reglas explicables, `GET /iam/risks`)
| Código | Condición | Severidad |
|---|---|---|
| `inactive` | sin actividad > 90 días (`IAM_INACTIVE_DAYS`) y cuenta activa | alta si privilegiada |
| `excessive_permissions` | ≥5 permisos y ≥70 % sin uso en el periodo observado | alta si privilegiada |
| `privileged_no_mfa` | humana privilegiada con MFA = no | crítica |
| `service_no_rotation` | credencial de servicio/clave estática de > 90 días | alta si privilegiada |
| `weak_auth` | método débil (`password`, `basic`, `ntlm`, `static_api_key`, `sms`) en cuenta privilegiada o de servicio | alta si privilegiada |
| `dangerous_trust` | identidad no privilegiada puede asumir una privilegiada (`can_assume`) | alta |

**Datos ausentes ⇒ hallazgo `unverified`**, nunca «segura» ni «inactiva»: p. ej. sin `lastActivityAt` se informa «no se puede confirmar».

## Reducción de privilegios
`POST /iam/identities/{id}/propose-reduction` calcula (con la analítica de mínimo privilegio) qué conservar y qué quitar **solo si hay datos de uso reales**; devuelve `applied:false`. SentinelMesh **no modifica privilegios reales**: aplicar el recorte es una acción de riesgo alto que debe pasar por un playbook ASSISTED con aprobación firmada (`propose_permission_change`) y, hoy, solo se registra en el ejecutor de laboratorio. Para roles AWS existe además el flujo previo `POST /iam/audit-roles` (Terraform + aprobación).

## Relacionar con activos
`assetIds` y relaciones `has_access/admin_of/can_assume` unen identidades con activos; alimentan la prioridad (privilegios alcanzables) y las rutas de ataque.
