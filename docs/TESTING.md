# Pruebas y validación

## Comandos
```bash
npm run lint                         # ESLint + eslint-plugin-security, 0 avisos permitidos
npm test                             # API (Jest) + consola (Vitest)
npm run demo:enterprise -w apps/api  # escenario reproducible de 12 pasos con aserciones
npm run perf -w apps/api             # sonda de rendimiento (PERF_VULNS, PERF_SIGNALS, PERF_CONCURRENCY)
pytest -q services/analytics         # analítica
python docs/tools/routes.py          # regenera la tabla de rutas de API_DOCUMENTATION.md
```

## Resultados medidos (2026-11-17, Windows 11, Node 24, un solo proceso)
| Suite | Resultado | Notas |
|---|---|---|
| API sin servicios externos | **191 pasan, 30 omitidas** (221) | las omitidas necesitan Redis, PostgreSQL, moto, Terraform o el servicio Python |
| API + PostgreSQL 16 real (Docker) | **199 pasan, 22 omitidas** | añade RLS, inmutabilidad (triggers), unicidad, dos réplicas, carreras |
| API + PostgreSQL + Redis (medición anterior en la sesión) | **202 pasan, 21 omitidas** (223) | las 21 restantes necesitan moto (emulador AWS), Terraform y el contrato con Python |
| Consola (Vitest) | 8 pasan | las vistas nuevas **no tienen pruebas unitarias ni Playwright**; solo compilan, pasan lint y se probaron las rutas de API que consumen |
| Analítica (pytest) | 8 pasan | medido al inicio de la sesión |
| `npm run lint` | 0 avisos | |
| Demo empresarial | 12 pasos, todas las aserciones | fuente **simulada** (`sim-edr`), ejecutor de laboratorio |

Cobertura funcional nueva: autenticación y MFA (12), CTEM (18), IAM (5), conectores (12), casos/evidencia/correlación (9), SOAR (15), notificaciones (7), dashboard/informes/IA/privacidad/observabilidad (15), seguridad OWASP (10), PostgreSQL empresarial (3).

## Pruebas de seguridad (autorizadas, locales, datos de prueba)
`security.spec.ts`: BOLA en 21 operaciones por id y 23 listados con un tenant hostil · todas las rutas protegidas rechazan credenciales ausentes/malformadas · 8 escaladas de privilegio · asignación masiva y contaminación de prototipos · inyección en consultas · cuerpo sobredimensionado · cabeceras · detección de manipulación de la auditoría. Más: manipulación de evidencia (`cases.spec.ts`), aprobación alterada (`soar.spec.ts`), exposición de secretos (`connectors.spec.ts`, `platform.spec.ts`), SSRF (`connectors.spec.ts`, `notifications.spec.ts`).
**No** se hizo pentest manual ni DAST contra una instancia desplegada.

## Rendimiento (sonda `npm run perf`)
Metodología: proceso único, repositorios en memoria, sin red ni PostgreSQL, sin límite de tasa; 500 vulnerabilidades, 2 000 señales, 50 activos. Medición 2026-11-17:

| Escenario | Peticiones | Concurrencia | req/s | p50 ms | p95 ms |
|---|---|---|---|---|---|
| Crear 50 activos | 50 | 1 | 77 | 5,7 | 24,2 |
| Crear 500 vulnerabilidades (cada una repriorizada con el grafo) | 500 | 1 | 72 | 12,4 | 27,4 |
| Ingerir 2 000 señales en lotes de 500 (deduplicación + correlación + playbooks) | 4 | 1 | — | 2 361 | 3 219 |
| `GET /vulns?limit=50` | 60 | 1 | 36 | 16,7 | 79,6 |
| `GET /ctem/priorities` | 30 | 1 | 27 | 27,1 | 90,1 |
| `GET /dashboard/executive` | 30 | 1 | 21 | 47 | 79 |
| `GET /dashboard/executive` | 100 | 50 | 18 | 3 032 | 3 151 |
| `GET /ctem/attack-paths` | 20 | 1 | 15 | 49,7 | 273 |
| Informe PDF técnico | 5 | 1 | 4 | 235 | 360 |
| Informe PDF ejecutivo | 5 | 1 | 19 | 51,5 | 56 |

Memoria al final: ~1 GiB de heap (los repositorios en memoria clonan cada lectura).

**Lectura honesta**: son medidas de *este código en esta máquina*, no de capacidad. Hallazgos reales: (1) la ingesta de señales cuesta ~2,4 s por lote de 500 porque la correlación recorre todas las señales de la organización por cada señal nueva (O(n²)); (2) el dashboard y los listados cargan y filtran toda la organización en el proceso, por lo que con 50 clientes concurrentes la latencia se satura (CPU de un único hilo); (3) con PostgreSQL añadirá latencia de red. Acciones en `ROADMAP.md` (filtros/orden en SQL, índices por activo/IP, ventana acotada).

## Límites de la verificación
Conectores contra mocks de protocolo (no servicios reales) · imágenes, Helm y los workflows de CI no se ejecutaron · sin pruebas de carga sostenida ni de recuperación ante desastres · sin pruebas de accesibilidad formales.
