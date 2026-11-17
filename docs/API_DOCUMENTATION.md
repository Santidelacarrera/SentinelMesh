# API de SentinelMesh

Base: `/api/v1`. Formato JSON. Todas las entradas se validan con esquemas **estrictos** (campos desconocidos → `400`, lo que impide la asignación masiva).
Esta tabla se **genera a partir de los controladores** (no se escribe a mano); regenerar con `python docs/tools/routes.py` (ver `TESTING.md`) si cambian las rutas.

## Autenticación
| Mecanismo | Uso |
|---|---|
| Sesión de usuario | `POST /auth/login` `{org,email,password,totp?}` → `accessToken` (`smt.…`, 15 min) y `refreshToken` (`smr.…`, rotatorio). Enviar `Authorization: Bearer <accessToken>`. |
| Renovación | `POST /auth/refresh` `{refreshToken}`. Reutilizar un refresh ya usado revoca toda la familia de sesiones. |
| OIDC | `OIDC_ISSUER`/`OIDC_AUDIENCE`: tokens JWT firmados (RS/ES/PS/EdDSA); los claims `sentinel_org` y `sentinel_role` fijan tenant y rol. Un IdP nunca puede otorgar `platform_admin`. |
| Clave API | Cabecera `x-api-key` (heredado; desactivar con `AUTH_ALLOW_API_KEYS=0`). |

## Errores
`400` validación · `401` credenciales · `402` función no incluida en el plan · `403` permiso/rol/separación de funciones · `404` no existe **o pertenece a otra organización** · `409` conflicto/estado · `429` límite de tasa · `502` fallo de un sistema externo (conector).

## Rutas
| M�todo | Ruta | Permiso / rol | Funci�n del plan |
|---|---|---|---|
| POST | `/api/v1/ai/explain` | ai:use | ai |
| GET | `/api/v1/ai/settings` | ai:use | ai |
| POST | `/api/v1/ai/settings` | settings:manage | ai |
| GET | `/api/v1/approvals` | role viewer |  |
| POST | `/api/v1/approvals/:id/decision` | role approver |  |
| GET | `/api/v1/assets` | role viewer |  |
| POST | `/api/v1/assets` | role analyst |  |
| GET | `/api/v1/audit` | role viewer |  |
| POST | `/api/v1/auth/login` | � |  |
| POST | `/api/v1/auth/logout` | role viewer |  |
| POST | `/api/v1/auth/mfa/begin` | role viewer |  |
| POST | `/api/v1/auth/mfa/confirm` | role viewer |  |
| POST | `/api/v1/auth/mfa/disable` | role viewer |  |
| POST | `/api/v1/auth/password` | role viewer |  |
| POST | `/api/v1/auth/password/reset` | � |  |
| POST | `/api/v1/auth/refresh` | � |  |
| GET | `/api/v1/auth/sessions` | role viewer |  |
| GET | `/api/v1/cases` | cases:read | cases |
| POST | `/api/v1/cases` | cases:write | cases |
| GET | `/api/v1/cases/:id` | cases:read | cases |
| POST | `/api/v1/cases/:id/assign` | cases:write | cases |
| POST | `/api/v1/cases/:id/comments` | cases:write | cases |
| GET | `/api/v1/cases/:id/evidence` | evidence:read | cases |
| POST | `/api/v1/cases/:id/evidence` | evidence:write | cases |
| POST | `/api/v1/cases/:id/evidence/export` | evidence:export | cases |
| POST | `/api/v1/cases/:id/links` | cases:write | cases |
| POST | `/api/v1/cases/:id/status` | cases:write | cases |
| GET | `/api/v1/cases/:id/timeline` | cases:read | cases |
| GET | `/api/v1/connectors` | connectors:read | connectors |
| POST | `/api/v1/connectors` | connectors:manage | connectors |
| GET | `/api/v1/connectors/:id` | connectors:read | connectors |
| POST | `/api/v1/connectors/:id` | connectors:manage | connectors |
| POST | `/api/v1/connectors/:id/disable` | connectors:manage | connectors |
| POST | `/api/v1/connectors/:id/enable` | connectors:manage | connectors |
| POST | `/api/v1/connectors/:id/sync` | connectors:sync | connectors |
| POST | `/api/v1/connectors/:id/test` | connectors:manage | connectors |
| GET | `/api/v1/connectors/catalog` | connectors:read |  |
| GET | `/api/v1/connectors/health` | connectors:read | connectors |
| GET | `/api/v1/correlations` | cases:read | cases |
| GET | `/api/v1/correlations/:id` | cases:read | cases |
| POST | `/api/v1/correlations/:id/decision` | cases:write | cases |
| GET | `/api/v1/credentials` | role viewer |  |
| GET | `/api/v1/ctem/attack-paths` | paths:read | ctem_advanced |
| GET | `/api/v1/ctem/priorities` | vulns:read | vulns |
| POST | `/api/v1/ctem/reprioritize` | vulns:write | vulns |
| GET | `/api/v1/dashboard/executive` | dashboard:read | dashboard |
| GET | `/api/v1/evidence/:id` | evidence:read | cases |
| GET | `/api/v1/evidence/:id/content` | evidence:export | cases |
| POST | `/api/v1/evidence/:id/metadata` | evidence:write | cases |
| POST | `/api/v1/evidence/:id/verify` | evidence:read | cases |
| GET | `/api/v1/executions` | role viewer |  |
| GET | `/api/v1/executions/:id` | role viewer |  |
| GET | `/api/v1/executions/:id/forensics` | role viewer |  |
| GET | `/api/v1/exposures/findings` | exposures:read | ctem_advanced |
| GET | `/api/v1/exposures/history` | exposures:read | ctem_advanced |
| POST | `/api/v1/exposures/observe` | exposures:write | ctem_advanced |
| GET | `/api/v1/exposures/summary` | role viewer |  |
| GET | `/api/v1/findings` | role viewer |  |
| GET | `/api/v1/findings/:id/trace` | role viewer |  |
| POST | `/api/v1/iam/audit-roles` | role analyst |  |
| GET | `/api/v1/iam/audits` | role viewer |  |
| GET | `/api/v1/iam/changes` | identities:read | iam |
| GET | `/api/v1/iam/identities` | identities:read | iam |
| POST | `/api/v1/iam/identities` | identities:write | iam |
| GET | `/api/v1/iam/identities/:id` | identities:read | iam |
| POST | `/api/v1/iam/identities/:id/propose-reduction` | identities:write | iam |
| POST | `/api/v1/iam/identities/bulk` | identities:write | iam |
| GET | `/api/v1/iam/risks` | identities:read | iam |
| GET | `/api/v1/iam/summary` | identities:read | iam |
| GET | `/api/v1/incidents` | role viewer |  |
| GET | `/api/v1/incidents/:id` | role viewer |  |
| POST | `/api/v1/incidents/trigger` | role analyst |  |
| POST | `/api/v1/intel/import` | intel:write | vulns |
| GET | `/api/v1/inventory/assets` | assets:read | discovery |
| POST | `/api/v1/inventory/assets` | assets:write | discovery |
| GET | `/api/v1/inventory/assets/:id` | assets:read | discovery |
| POST | `/api/v1/inventory/assets/:id/ownership/challenge` | assets:verify | discovery |
| POST | `/api/v1/inventory/assets/:id/ownership/verify` | assets:verify | discovery |
| POST | `/api/v1/inventory/assets/:id/scope` | assets:verify | discovery |
| POST | `/api/v1/inventory/assets/:id/tls-check` | exposures:write | ctem_advanced |
| POST | `/api/v1/inventory/assets/bulk` | assets:write | discovery |
| POST | `/api/v1/inventory/assets/stale-check` | assets:write | ctem_advanced |
| POST | `/api/v1/inventory/relations` | assets:write | discovery |
| GET | `/api/v1/me` | role viewer |  |
| GET | `/api/v1/ops/health` | settings:manage |  |
| GET | `/api/v1/plan` | role viewer |  |
| GET | `/api/v1/platform/orgs` | platform:manage |  |
| POST | `/api/v1/platform/orgs` | platform:manage |  |
| POST | `/api/v1/platform/orgs/:id` | platform:manage |  |
| POST | `/api/v1/privacy/erase-user` | privacy:manage | privacy_tools |
| GET | `/api/v1/privacy/export` | privacy:manage | privacy_tools |
| GET | `/api/v1/privacy/retention` | privacy:manage | privacy_tools |
| POST | `/api/v1/privacy/retention` | privacy:manage | privacy_tools |
| POST | `/api/v1/privacy/retention/apply` | privacy:manage | privacy_tools |
| POST | `/api/v1/remediations/simulate` | role analyst |  |
| GET | `/api/v1/reports` | reports:read | reports |
| POST | `/api/v1/reports` | reports:generate | reports |
| GET | `/api/v1/reports/:id/pdf` | reports:read | reports |
| GET | `/api/v1/roles` | roles:manage |  |
| POST | `/api/v1/roles` | roles:manage |  |
| POST | `/api/v1/scans/ingest` | role analyst |  |
| POST | `/api/v1/secrets/rotate` | role analyst |  |
| GET | `/api/v1/signals` | signals:read |  |
| POST | `/api/v1/signals` | signals:write |  |
| GET | `/api/v1/soar/approvals` | approvals:read | soar |
| GET | `/api/v1/soar/automation` | runs:read | soar |
| POST | `/api/v1/soar/automation` | automation:manage | soar |
| GET | `/api/v1/soar/channels` | channels:read | soar |
| POST | `/api/v1/soar/channels` | channels:manage | soar |
| POST | `/api/v1/soar/channels/:id` | channels:manage | soar |
| POST | `/api/v1/soar/channels/:id/test` | channels:manage | soar |
| POST | `/api/v1/soar/identity-scan` | runs:trigger | soar |
| POST | `/api/v1/soar/kill-switch` | runs:approve | soar |
| GET | `/api/v1/soar/log` | channels:read | soar |
| GET | `/api/v1/soar/playbooks` | playbooks:read | soar |
| POST | `/api/v1/soar/playbooks` | playbooks:write | soar |
| POST | `/api/v1/soar/playbooks/:key/state` | playbooks:enable | soar |
| GET | `/api/v1/soar/playbooks/:key/versions` | playbooks:read | soar |
| POST | `/api/v1/soar/playbooks/install-defaults` | playbooks:write | soar |
| GET | `/api/v1/soar/runs` | runs:read | soar |
| GET | `/api/v1/soar/runs/:id` | runs:read | soar |
| POST | `/api/v1/soar/runs/:id/stop` | runs:approve | soar |
| POST | `/api/v1/soar/trigger` | runs:trigger | soar |
| GET | `/api/v1/users` | users:manage |  |
| POST | `/api/v1/users` | users:manage |  |
| POST | `/api/v1/users/:id/disable` | users:manage |  |
| POST | `/api/v1/users/:id/enable` | users:manage |  |
| POST | `/api/v1/users/:id/mfa-reset` | users:manage |  |
| POST | `/api/v1/users/:id/reset-token` | users:manage |  |
| POST | `/api/v1/users/:id/revoke-sessions` | sessions:manage |  |
| POST | `/api/v1/users/:id/role` | users:manage |  |
| GET | `/api/v1/vulns` | vulns:read | vulns |
| POST | `/api/v1/vulns` | vulns:write | vulns |
| POST | `/api/v1/vulns/:id/status` | vulns:write | vulns |
| POST | `/api/v1/vulns/import-findings` | vulns:write | vulns |
| GET | `/healthz` | � |  |
| GET | `/metrics` | � |  |
| GET | `/readyz` | � |  |

Además: `GET /healthz` (vida), `GET /readyz` (BD y cola), `GET /metrics` (Prometheus; `METRICS_TOKEN`).
Los permisos están definidos en `apps/api/src/auth/rbac.ts`; los planes en `apps/api/src/platform/entitlements.ts`.
