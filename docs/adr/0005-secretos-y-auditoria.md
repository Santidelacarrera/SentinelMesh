# ADR-0005 · Enmascarado de secretos y auditoría encadenada
- **Fecha:** 2026-10-13 · **Estado:** aceptada

**Decisión.** Los secretos detectados se **enmascaran en el acto** (`AKIA****LE`); el valor completo no se persiste en ningún sitio (ni en el informe archivado, ni en hallazgos, ni en la auditoría, ni en la evidencia forense). La traza de auditoría es **append-only y encadenada por hash** por organización; cualquier alteración rompe la cadena y `verify()` la detecta.

**Bug encontrado y corregido en esta rama.** El hash se calculaba sobre el objeto con claves `undefined`; al releer desde JSONB esas claves desaparecen y la cadena aparecía rota. Ahora la carga se **normaliza por JSON antes de hashear** (test de regresión `audit trail persistence round-trip`).
