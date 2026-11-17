# Evidencia forense

## Garantías implementadas
| Garantía | Cómo |
|---|---|
| Original no modificable | los bytes se escriben **una sola vez** en el almacén de objetos (clave única; no existe API de borrado ni de reescritura); un trigger de PostgreSQL impide cambiar `sha256`, `objectKey` o `caseId` y borrar la fila |
| Integridad | SHA-256 al capturar; se **re-verifica** en cada lectura, descarga y exportación; si no coincide → `409`, entrada `MISMATCH` en la custodia y `evidence.integrity_failure` en la auditoría |
| Cadena de custodia | cada acceso añade una entrada (`captured, viewed, downloaded, exported, metadata_updated, integrity_verified`) con actor y hora; además queda en la auditoría encadenada |
| Cambios de metadatos | permitidos solo para metadatos descriptivos, con **motivo obligatorio** y registro antes/después |
| Exportación controlada | `POST /cases/{id}/evidence/export {purpose}` (permiso `evidence:export`): manifiesto con hashes, contenidos, custodia completa; cada elemento se verifica antes de salir; queda en la línea de tiempo y la auditoría; el manifiesto lleva su propio hash |
| Aislamiento | la evidencia pertenece a una organización y un caso; ids ajenos devuelven `404` |

Límite por elemento: 5 MiB (para artefactos grandes, guarda un manifiesto con la referencia y el hash).

## Núcleo previo (incidentes por anomalía de tráfico)
`collect_forensics` congela Prometheus/Loki/Kubernetes antes de cualquier contención, con SHA-256 y escritura única (`architecture.md`). Esas fuentes solo se probaron con dobles de las respuestas, no con servicios reales.

## Lo que no se afirma
**La admisibilidad legal de la evidencia no se ha evaluado** (cada exportación lo indica). Un administrador con acceso directo al almacenamiento o a la base de datos con rol propietario podría alterarlos fuera de la aplicación: usa *object lock*/WORM en el bucket y réplicas de auditoría para cubrir ese caso. La evidencia no se elimina con la retención configurable.
