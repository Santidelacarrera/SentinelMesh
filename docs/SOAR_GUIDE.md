# Guía SOAR

## Playbook
Disparador (`signal | finding | vulnerability | exposure | identity`) · condiciones (`eq, neq, gte, lte, in, contains, exists` sobre campos del evento; `gte` entiende severidades) · acciones (hasta 10) · responsable · nivel de riesgo · modo · versión **inmutable** (publicar crea una versión nueva; activar/desactivar es un ajuste aparte). Plantillas `{{trigger.campo}}` sin evaluación de código.

Acciones: `create_case`, `create_ticket`, `notify`, `tag` (seguras, internas) y `propose_account_lock | propose_session_revoke | propose_endpoint_isolation | propose_config_fix | propose_patch_request | propose_permission_change` (**de riesgo**). El nivel de riesgo efectivo es el máximo entre el declarado y el de sus acciones (no se puede declarar «bajo» un playbook que bloquea cuentas).

Seis playbooks base (`POST /soar/playbooks/install-defaults`): credencial expuesta, endpoint comprometido, vulnerabilidad de prioridad inmediata, acceso sospechoso, activo expuesto confirmado, privilegios excesivos.

## Niveles
| Nivel | Comportamiento |
|---|---|
| **OBSERVE** | detecta, registra y avisa (`notify`, `create_case`). Todo lo demás queda *skipped* con el motivo. Cambia nada. |
| **ASSISTED** (por defecto) | las acciones seguras se ejecutan; cada acción de riesgo crea una **aprobación** y la ejecución se pausa hasta la firma de otra persona. |
| **AUTOMATED** | **apagado por defecto**. Requiere que un administrador active `automatedEnabled`, fije el techo y una lista blanca `allowedAutoActions`. Aun así: el riesgo **alto** siempre pide aprobación, y hay un presupuesto `maxActionsPerHour`. |

El modo efectivo es `min(modo del playbook, techo de la organización)`; con el *kill switch* siempre es OBSERVE.

## Aprobación
`GET /soar/approvals` muestra la acción y los parámetros exactos. Se decide con `POST /approvals/{id}/decision` (rol approver/admin). La firma cubre el **hash del paso** (`runId, índice, acción, parámetros`); al aprobar se recalcula y se verifica la firma: un paso alterado después de pedirse **no se ejecuta** (la ejecución falla). Quien provocó el run no puede aprobarlo (separación de funciones). Rechazar detiene el run.

## Ejecución, idempotencia, parada
- Un run es único por *(playbook, tipo de disparador, id de entidad)*; reenviar el evento no lo repite. Cada paso lleva `idempotencyKey`; el ejecutor la usa.
- **Único ejecutor incluido: `lab`**: registra el efecto (`LabEffect`) y dice explícitamente que no tocó ningún sistema real. Para actuar sobre sistemas reales haría falta un ejecutor nuevo con autorización adicional y permisos de escritura en el conector (`ROADMAP.md`).
- `POST /soar/runs/{id}/stop` y `POST /soar/kill-switch {on, reason}` (approver/admin): el interruptor detiene los runs pendientes, fuerza OBSERVE y hace que una aprobación tardía no ejecute nada. Todo queda auditado y avisado por los canales.
- Historial completo en `run.history` y en la auditoría (`playbook.*`).

## Recuperación
Los pasos del ejecutor de laboratorio no necesitan *rollback*. Para el núcleo previo (rotación de credenciales, WAF/IAM por Terraform) siguen vigentes sus mecanismos: healthcheck + vuelta a la versión anterior, plan guardado y aplicación idempotente (`architecture.md`).
