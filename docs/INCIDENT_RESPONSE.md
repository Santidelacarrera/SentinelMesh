# Gestión de incidentes

## Origen de un caso
- **Correlación** (`signals → correlación → caso`): varias señales que comparten activo, identidad, IP pública, dominio o CVE dentro de una ventana (30 min, `CORRELATION_WINDOW_SEC`) se agrupan. Cada vínculo guarda **tipo, valor, fuente y confianza**; la confianza total es 1 − Π(1 − c) sobre la razón más fuerte de cada tipo. Las IP privadas compartidas **no** cuentan como evidencia. Si el riesgo ≥ 60 (`CORRELATION_AUTO_CASE_RISK`) se abre un caso automáticamente (una vez por correlación).
- **Playbook** (`create_case`) o **manual** (`POST /cases`).

## La correlación es una hipótesis
Estado `probable` hasta que un analista la confirma o descarta con una nota (`POST /correlations/{id}/decision`); la decisión queda en la línea de tiempo y en la auditoría. El caso dice «probable, no confirmado» en su descripción.

## Ciclo de vida
`new → investigating → contained ⇄ remediating → resolved → closed` (transiciones validadas; `resolved` y `closed` exigen una nota; `closed` es terminal). Campos: severidad, activos, identidades, vulnerabilidades, señales, evidencias, responsable, **acciones realizadas** (separadas de las **recomendaciones**), línea de tiempo cronológica inmutable (apertura, estados, asignaciones, comentarios, evidencia, acciones de playbooks), fechas de apertura y cierre. Los textos pasan por redacción de secretos.

## Procedimiento sugerido
1. Revisar el caso y su correlación (`/cases/{id}`; asistente: `POST /ai/explain {kind:"case"}` para un resumen con fuentes).
2. Asignar responsable y pasar a *investigating*.
3. Capturar evidencia **antes** de contener (`FORENSICS.md`).
4. Revisar propuestas pendientes en `/soar/approvals` (aislamiento, revocación de sesiones…); aprobar solo tras verificar. Nada se ejecuta sin firma; hoy el ejecutor es de laboratorio.
5. Registrar lo hecho (comentarios/acciones), pasar a *contained/remediating/resolved* con nota.
6. Informe de incidente PDF (`POST /reports {kind:"incident", caseId}`) y cierre.

## Notificaciones
Canales email/Slack/Teams con severidad mínima, eventos, ventana de agrupación, silenciamiento, escalado y control de tormentas. Un aviso solo figura como **entregado** si el proveedor lo confirmó (Slack: cuerpo `ok`; Teams: 2xx; email: destinatarios aceptados por SMTP); los fallos se registran y pueden escalar a otro canal.
