# ADR-0002 · Aprobación firmada y ligada al hash del plan
- **Fecha:** 2026-10-13 · **Estado:** aceptada

**Contexto.** Ninguna acción destructiva (revocar, aplicar WAF/IAM, aislar) puede ocurrir sin una decisión humana explícita y auditable.

**Decisión.** (1) Cada acción destructiva se declara `destructive` y el motor **pausa** hasta tener una aprobación. (2) La decisión se **firma** (HMAC/Ed25519/KMS) sobre `{aprobación, plan, hash del plan, decisión, persona, instante}`. (3) El motor recomprueba firma, hash y que el plan no cambió **antes** de ejecutar. (4) Los **adaptadores re-verifican** la prueba: sin ella rechazan la llamada. (5) **Separación de funciones:** quien solicita no puede aprobar. (6) La decisión es *compare-and-set*: una vez tomada es definitiva (409).

**Alternativas descartadas.** Confiar solo en el estado `approved` de la BD (manipulable); firmar solo la aprobación sin el hash del plan (permitiría aprobar A y ejecutar B).

**Consecuencias.** Un plan manipulado, una firma forjada o una aprobación para otro plan terminan en fallo sin efectos (tests `refuses to execute a plan tampered…`, `forged approvals cannot unlock adapters`).
