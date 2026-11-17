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
| API sin servicios externos | **≈195 pasan, ≈31 omitidas** | las omitidas necesitan Redis, PostgreSQL, moto, Terraform o el servicio Python |
| **API con PostgreSQL 16 + Redis 7 + moto + servicio Python (Docker/venv)** | **224 pasan, 4 omitidas** (228) | las 4 omitidas necesitan el binario de Terraform. Añade RLS y triggers reales, dos réplicas, carreras, bloqueos Redis, adaptadores AWS contra moto, el conector AWS con el SDK real contra moto y el contrato Python↔TypeScript |
| Consola (Vitest) | **17 pasan** | 9 pruebas nuevas de las vistas (estados reales de conectores, permisos, estados vacíos, datos ausentes) |
| Analítica (pytest) | 8 pasan | medido al inicio de la sesión |
| `npm run lint` | 0 avisos | |
| Demo empresarial | 12 pasos, todas las aserciones | fuente **simulada** (`sim-edr`), ejecutor de laboratorio |

moto emula la API de AWS; **no es AWS** (no reproduce todas sus reglas).

Cobertura funcional nueva: autenticación y MFA (12), CTEM (18), IAM (5), conectores (12), casos/evidencia/correlación (9), SOAR (15), notificaciones (7), dashboard/informes/IA/privacidad/observabilidad (15), seguridad OWASP (10), PostgreSQL empresarial (3).

## Pruebas de seguridad (autorizadas, locales, datos de prueba)
`security.spec.ts`: BOLA en 21 operaciones por id y 23 listados con un tenant hostil · todas las rutas protegidas rechazan credenciales ausentes/malformadas · 8 escaladas de privilegio · asignación masiva y contaminación de prototipos · inyección en consultas · cuerpo sobredimensionado · cabeceras · detección de manipulación de la auditoría. Más: manipulación de evidencia (`cases.spec.ts`), aprobación alterada (`soar.spec.ts`), exposición de secretos (`connectors.spec.ts`, `platform.spec.ts`), SSRF (`connectors.spec.ts`, `notifications.spec.ts`).
**No** se hizo pentest manual ni DAST contra una instancia desplegada.

## Rendimiento (sonda `npm run perf`)
Metodología: proceso único, repositorios en memoria, sin red ni PostgreSQL, sin límite de tasa; 500 vulnerabilidades, 2 000 señales, 50 activos.

| Escenario | Antes de optimizar | Después | Cambio |
|---|---|---|---|
| Ingerir señales, lote de 500 (deduplicación + correlación + playbooks), p50 | 2 361 ms | **355 ms** | correlación indexada por atributo compartido (una carga por lote, no un escaneo por señal) |
| Dashboard ejecutivo, 50 clientes concurrentes, p95 | 3 151 ms | **282 ms** | peticiones idénticas simultáneas comparten un cálculo; resultado reutilizado `DASHBOARD_CACHE_SEC` (5 s) |
| `GET /vulns?limit=50`, p50 / p95 | 16,7 / 79,6 ms | 28,3 / 91,4 ms | sin cambios de código (variación de la máquina) |
| `GET /ctem/priorities`, p50 | 27 ms | 33 ms | ídem |
| Informe PDF técnico, p50 | 236 ms | ≈230 ms | |

Nota: el dashboard secuencial de la segunda columna sale en 3 ms porque la caché de 5 s lo sirve; la medición honesta del cálculo en frío son los ≈47 ms de la primera.
Memoria final ≈1 GiB de heap (los repositorios en memoria clonan cada lectura).

**Lectura honesta**: son medidas de *este código en esta máquina*, no de capacidad. Siguen pendientes: filtros, orden y paginación de los listados en SQL (hoy cargan toda la organización en el proceso) y medir con PostgreSQL y red reales (`ROADMAP.md`).

## Límites de la verificación
Conectores contra mocks de protocolo (no servicios reales) · imágenes, Helm y los workflows de CI no se ejecutaron · sin pruebas de carga sostenida ni de recuperación ante desastres · sin pruebas de accesibilidad formales.
