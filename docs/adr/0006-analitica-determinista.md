# ADR-0006 · Analítica determinista, sin LLM, con fallback local
- **Fecha:** 2026-10-13 · **Estado:** aceptada

**Decisión.** Correlación de severidad, menor privilegio y resumen forense son **deterministas y explicables**: cada resultado trae su justificación y cada línea del resumen cita su evidencia (nada que alucinar, nada de pago). El servicio Python (FastAPI) tiene un **espejo local idéntico** en la API: si el servicio no responde se usa el local (fail-safe, nunca fail-open; un secreto nunca se degrada). La paridad entre ambos se comprueba con un test de contrato.
