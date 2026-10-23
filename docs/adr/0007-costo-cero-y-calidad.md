# ADR-0007 · Costo $0, calidad y seguridad
- **Fecha:** 2026-10-13 · **Estado:** aceptada

**Decisión.** Solo software libre/gratuito (NestJS, React, FastAPI, PostgreSQL, Redis, moto como emulador). Sin APIs de pago ni credenciales reales: las claves `dev-*` solo existen fuera de producción. Puertas de calidad: **ESLint** (+ `eslint-plugin-security` y `react-hooks`) con 0 avisos permitidos, **`npm audit --audit-level=high`** incluyendo dependencias de desarrollo, **ruff** y **bandit** para Python, cobertura medida y CI que ejecuta todo con Postgres, Redis y el emulador de AWS como servicios.

**Dependencias.** Se subieron herramientas de desarrollo con vulnerabilidades altas/críticas (Jest 29→30, Vitest 2→5, Vite 5→8, jsdom 30) y se retiró `@testing-library/jest-dom` (arrastraba un Vitest vulnerable; no era imprescindible). Resultado: `npm audit` = 0 vulnerabilidades.

**No disponible.** Semgrep: el registro de reglas está bloqueado en este entorno; se sustituye por ESLint-security + bandit y queda anotado como pendiente.
