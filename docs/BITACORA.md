# Bitácora de SentinelMesh — Nexus Security & AI Lab

> Estado: **terminado autónomo, pendiente de aprobación de Santiago.** Esta bitácora vive en el repositorio porque la nota del proyecto en el vault no es accesible
> desde la sesión que hizo el trabajo; copiarla a la nota es un pendiente (ver abajo). No se tocaron estados `aprobado_santiago` / `aprobado_sistema`.
> Rama de trabajo: `feat/sentinelmesh-autonomo-2026-10-12` (base `main`).

## 1. Definición de terminado (6 condiciones) y evidencia

| # | Condición | Estado | Evidencia |
|---|---|---|---|
| 1 | Tareas del proyecto cumplidas con evidencia | ✔ | Ver §2 |
| 2 | Pruebas automatizadas pasando (comando + salida) | ✔ | Ver §3 |
| 3 | Seguridad y lint sin errores altos | ✔ | Ver §4 (ESLint 0 avisos, `npm audit --audit-level=high` exit 0, ruff y bandit limpios) |
| 4 | README con instalación, prueba y uso reproducibles | ✔ | [`README.md`](../README.md); reproducido en un clon limpio (`npm ci`, `lint`, `build`, `test`, `simulate`, `pytest`, arranque de la API y `/healthz`) |
| 5 | Bitácora de decisiones con fecha y motivo | ✔ | §5 y [`docs/adr/`](adr) |
| 6 | Lista de pendientes para Santiago | ✔ | §6 |

## 2. Tareas de la nota y evidencia
| Tarea | Resultado | Evidencia |
|---|---|---|
| Terminar el núcleo mínimo con pruebas | Hecho. Camino completo ingesta → correlación → plan → aprobación firmada → ejecución → auditoría; rotación sin cortes; incidentes con evidencia congelada | Suite del núcleo: ver §3. Mapa criterio → prueba en el README («Definición de terminado: evidencia por criterio») |
| Documentar arquitectura y decisiones | Hecho | [`docs/architecture.md`](architecture.md), ADR-0001…0007, esta bitácora |
| No agregar componentes de nube hasta que el núcleo esté probado | Cumplido: **esta rama no añade ningún componente de nube**. Los adaptadores AWS que ya estaban en `main` siguen desactivados por defecto | ADR-0001; test `core runs at cost $0 by default` (sin `INFRA_MODE` ningún puerto es de nube) |

## 3. Pruebas: comandos ejecutados y salida
Ejecución final del 2026-10-13 sobre el commit de esta rama. Además se reprodujo en un **clon limpio** (`git clone` + `npm ci` + `lint` + `build` + `npm test` sin servicios: 77 pasadas / 20 omitidas por falta de servicios; `simulate`; arranque de la API y `/healthz`; `pip install -r requirements-dev.txt` + `pytest`).

**Bugs reales encontrados por la verificación y corregidos en esta rama:** (1) cadena de auditoría rota tras releer JSONB; (2) `npm run simulate -- --reject` ignoraba el flag (el script raíz no reenviaba argumentos): ahora funciona y el CI lo comprueba; (3) `ruff` daba resultados distintos según el directorio desde el que se lanzara (config explícita); (4) los scripts de demo/simulación fallaban si había `REDIS_URL`/`DATABASE_URL` en el entorno.
```
$ npm test   # sin servicios externos
Test Suites: 4 skipped, 6 passed, 6 of 10 total
Tests:       20 skipped, 77 passed, 97 total
      Tests  8 passed (8)
[exit 0]

$ npm run test:coverage -w apps/api   # con Redis, Postgres, emulador AWS y servicio de analítica
Statements   : 93.88% ( 1429/1522 )
Branches     : 75.52% ( 571/756 )
Functions    : 92.09% ( 326/354 )
Lines        : 98.26% ( 1021/1039 )
Test Suites: 10 passed, 10 total
Tests:       99 passed, 99 total
[exit 0]

$ npm test -w apps/web
 Test Files  2 passed (2)
      Tests  8 passed (8)   [exit 0]

$ npm run e2e -w apps/web   # Playwright (Chromium) contra la API demo
  ✓  6 e2e/console.spec.ts:77:1 › is usable on a phone (661ms)

  6 passed (21.4s)

$ npm run simulate
▶ 6. Outcome
   old credential v1 valid: false   infra changes: [{"op":"isolate","arg":"auth-api"}]
   audit entries: 21, hash-chain intact: true
[exit 0]

$ npm run simulate -- --reject
▶ 6. Outcome
   old credential v1 valid: true   infra changes: []
   audit entries: 18, hash-chain intact: true
[exit 0]

$ pytest -q services/analytics
4 passed, 1 warning in 0.46s
[exit 0]
```

## 4. Seguridad y lint
```
$ npm run lint
> sentinelmesh@0.1.0 lint
> eslint . --max-warnings=0

[exit 0]

$ npm run audit:deps
(informa de 20 vulnerabilidades MODERADAS transitorias de herramientas de prueba; 0 altas, 0 críticas)
npm run audit:deps = npm audit --audit-level=high → exit 0
[exit 0]

$ npm audit --omit=dev
found 0 vulnerabilities
[exit 0]

$ ruff check services/analytics
All checks passed!
[exit 0]

$ ruff format --check services/analytics
3 files already formatted
[exit 0]

$ bandit -q -r services/analytics/app -ll
(sin hallazgos)   [exit 0]
```
Notas: `npm audit` (completo, con dependencias de desarrollo) informa de **20 vulnerabilidades moderadas** transitorias de la herramienta de pruebas (Jest 30 → `babel-plugin-istanbul` → `js-yaml@3` → `argparse@1` → `sprintf-js`, sin parche publicado). **No se despliegan** (`npm audit --omit=dev` = 0) y no hay altas ni críticas. Semgrep no se pudo ejecutar (el registro de reglas está bloqueado en el entorno); lo sustituyen ESLint con `eslint-plugin-security` y bandit.

## 5. Decisiones tomadas por la sesión (con fecha y motivo)
| Fecha | Decisión | Motivo |
|---|---|---|
| 2026-10-13 | Trabajar sobre una rama nueva desde `main` y **no** incluir el trabajo pendiente de `claude/modest-fermi-ys3m1i` (réplicas sin estado, Terraform real, malla Istio) | Esos cambios son componentes de nube/infraestructura; la instrucción dice no añadirlos hasta probar el núcleo. Quedan listados como pendiente para que Santiago decida |
| 2026-10-13 | Núcleo = flujo completo con puertos simulados por defecto (ADR-0001) | Poder probarlo entero sin red, nube ni coste |
| 2026-10-13 | Subir Jest 29→30, Vitest 2→5, Vite 5→8, jsdom→30 y retirar `@testing-library/jest-dom` | Eliminar 2 críticas y 30 altas de dependencias de desarrollo (`npm audit`) sin cambiar el comportamiento: todas las pruebas siguen verdes |
| 2026-10-13 | Añadir ESLint (+security, react-hooks) con 0 avisos permitidos; ruff y bandit para Python | Condición 3 de la definición de terminado; fallos reales corregidos (`require()`, efectos de React, regex potencialmente costosa) |
| 2026-10-13 | Corregir el hash de la cadena de auditoría (normalizar por JSON antes de hashear) | Bug real: tras leer de PostgreSQL (JSONB) las claves `undefined` desaparecían y la cadena aparecía rota. Test de regresión añadido |
| 2026-10-13 | Detección de marcadores de posición sin regex con backtracking; límite de 4096 en el largo del secreto recibido | ESLint-security marcó posible ReDoS en un webhook público; ahora es lineal y está acotado (test de rendimiento) |
| 2026-10-13 | Test de contrato entre el servicio Python y el fallback local de la API | Garantiza que degradar al fallback no cambia los resultados |
| 2026-10-13 | `bootstrap()` exportado y probado como punto de entrada real | `main.ts` tenía 0 % de cobertura; ahora se prueba que el servidor arranca, responde `/healthz` y exige autenticación |
| 2026-10-13 | `gh` sin autenticar: el PR se abre con la API de GitHub disponible en la sesión | La instrucción prevé el bloqueo de `gh`; se usa la herramienta integrada, sin forzar nada |

## 6. Pendientes para Santiago
1. **Aprobar (o no) este PR.** No se ha hecho merge ni se han tocado los estados `aprobado_*`.
2. **Decidir sobre `claude/modest-fermi-ys3m1i`:** contiene trabajo *sin fusionar* — API sin estado para varias réplicas (repositorios async sobre PostgreSQL), `terraform plan/apply` real para WAF/IAM, y la malla de servicios Istio de «Segundo Cerebro» (con sus invariantes y documentación). Es nube/infraestructura, por eso quedó fuera de este PR; conviene abrirlo como PR aparte una vez aprobado el núcleo.
3. **Confirmar la lista real de microservicios y sus dependencias** para la malla (`infra/mesh/services.yaml` en esa rama usa supuestos).
4. **Copiar esta bitácora a la nota del proyecto en el vault** (la sesión no tiene acceso) y marcar allí el estado.
5. **Ejecutar Semgrep** localmente con reglas de la comunidad (aquí el registro está bloqueado).
6. **Probar contra AWS real en una cuenta de pruebas** antes de cualquier uso productivo: los adaptadores solo se han ejercitado contra un emulador (moto).
7. **Decidir licencia** del repositorio (no se asignó ninguna).
8. **Autenticar `gh`** en el entorno de sesiones si se quiere automatizar PRs con la CLI.

## 7. Riesgos conocidos
- Los adaptadores de nube (opcionales) no están probados contra servicios reales; el emulador no reproduce todas las reglas de AWS.
- Las 20 vulnerabilidades moderadas del árbol de desarrollo no tienen parche publicado (no afectan al código desplegado).
- `jsdom` 30 declara Node ≥ 22.22.2; en la sesión se probó con 22.22.0 y funcionó, pero un runner con Node más antiguo podría fallar (CI usa la última 22.x).
- Docker no estaba disponible en el entorno de la sesión: `docker-compose.yml` se validó con `docker compose config` y el Dockerfile paso a paso fuera de Docker, pero `docker compose up` no se ejecutó.
- Vitest/Jest suben de versión mayor: si el equipo trabaja con Node antiguo habría que fijar versiones.

*Pendiente de aprobación humana. No hacer merge sin aprobación de Santiago.*
