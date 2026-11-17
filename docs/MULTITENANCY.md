# Multi-tenencia

## Modelo
Una **organización** (`orgId`) posee usuarios, roles propios, activos, identidades, conectores, casos, evidencia, playbooks, canales, informes y configuración. La organización especial `org_platform` solo contiene a los **administradores de plataforma** y los perfiles de organización (plan, estado, retención).

## Aislamiento (defensa en profundidad)
1. **Aplicación**: toda operación de repositorio exige `orgId` (`Repo<T>`); el `orgId` sale de la sesión/credencial verificada, jamás del cuerpo (los esquemas estrictos rechazan `orgId`), y `x-tenant` debe coincidir.
2. **Base de datos**: RLS **forzada** en las 41 tablas de datos con `app.org_id` fijado por transacción; el rol de aplicación no es propietario ni `BYPASSRLS` y no puede `DELETE` salvo en tablas transitorias.
3. **Almacén de objetos**: claves con prefijo `…/{orgId}/…`; solo se alcanzan a través de registros de la organización.
4. **Tokens**: el token codifica la organización solo para *localizar* la sesión; el principal se construye con la sesión almacenada (un token con otra org no sirve).
5. **Respuesta uniforme**: un id de otra organización devuelve el mismo `404` que uno inexistente.

## Pruebas
`security.spec.ts` (barrido de 21 operaciones por id (9 lecturas, 12 escrituras) y 23 listados contra un tenant hostil), `auth.spec.ts`, y `pg-enterprise.spec.ts` contra **PostgreSQL real** (SQL directo cruzando tenants es rechazado por RLS; sin RLS no hay tablas). Cubre API, base de datos, evidencia, notificaciones, informes, búsquedas y exportaciones.

## Administración central
`POST/GET /platform/orgs`, `POST /platform/orgs/{id}` (plan, suspender/activar, retención) solo con rol `platform_admin` **y** desde `org_platform`. Suspender revoca las sesiones de la organización y bloquea el acceso. Cada acción se audita en la organización de plataforma y en la afectada. Un IdP/OIDC nunca puede conceder `platform_admin` ni acceso a `org_platform`.

## Roles
Roles base: `viewer < analyst < approver < admin` (+ `platform_admin`). Roles **propios** por organización (`POST /roles`, plan Enterprise): lista explícita de permisos, **solo aditivos** sobre `viewer`. Nadie cambia su propio rol.

## Planes
Ver `COMMERCIAL_MODEL.md`. Las funciones no incluidas devuelven `402`.
