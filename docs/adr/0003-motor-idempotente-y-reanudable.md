# ADR-0003 · Motor de orquestación idempotente y reanudable
- **Fecha:** 2026-10-13 · **Estado:** aceptada

**Decisión.** El estado de cada ejecución vive en el almacén, no en memoria. `advance()` deriva todo del estado persistido, por lo que un worker caído se reanuda re-ejecutando. Cada paso usa una **clave de idempotencia** (`ejecución:paso`) que los proveedores respetan (reintento ⇒ mismo resultado, sin duplicar versiones/efectos). Reintentos con backoff vía cola (BullMQ/Redis; en memoria para pruebas) y tope de intentos; un **bloqueo por ejecución** evita dos workers a la vez. Fallos que reintentar no arregla (healthcheck fallido ya revertido, plan manipulado) son **terminales**.

**Rotación sin cortes.** crear versión → apuntar el gestor de secretos → healthcheck con la nueva → *(aprobación)* → revocar la anterior. Si el healthcheck falla se revierte al valor anterior y la antigua nunca se toca; jamás se revoca la versión activa.

**Consecuencias.** Pruebas: caída del worker tras un efecto, reanudación, carrera de tres `advance`, tope de reintentos.
