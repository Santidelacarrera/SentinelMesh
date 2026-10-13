# ADR-0001 · Núcleo mínimo y puertos simulados por defecto
- **Fecha:** 2026-10-13 · **Estado:** aceptada · **Proyecto:** SentinelMesh — Nexus Security & AI Lab

**Contexto.** El producto prometía CTEM + higiene IAM + SOAR + aprobación humana. Para poder afirmar «terminado» hay que acotar qué es el núcleo y demostrarlo con pruebas, sin depender de nube ni de servicios de pago (regla de costo $0).

**Decisión.** El **núcleo mínimo** es el camino completo *ingesta → correlación con contexto → plan simulado (dry-run) → aprobación humana firmada → ejecución idempotente → auditoría inmutable*, más rotación de credenciales con healthcheck y respuesta a incidentes con evidencia forense. Todo lo que toca el exterior (gestor de secretos, WAF/IAM, aislamiento, healthcheck, recolector forense) está detrás de **puertos** (`workflow/ports.ts`) cuya implementación **por defecto es una simulación en proceso**. Los adaptadores de nube existen pero solo se activan con `INFRA_MODE=aws` y `NODE_ENV=production` los exige. En esta rama **no se añade ningún componente de nube nuevo**.

**Consecuencias.** (+) El núcleo se prueba entero en una máquina sin red ni cuentas (`npm test`). (+) Costo $0 verificable (test: sin `INFRA_MODE` ningún cliente de nube se construye). (−) El comportamiento contra nube real solo está probado contra un emulador (moto): queda como pendiente.
