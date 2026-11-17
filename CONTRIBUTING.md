# Contribuir

1. Trabaja en una rama (`git switch -c feat/lo-que-sea`). **Nunca** commits directos a `main`; los cambios se fusionan tras revisión humana.
2. `npm ci && npm run check` (lint + pruebas + build) debe pasar. Para cambios de base de datos añade una migración `db/migrations/NNNN_descripcion.sql` (aditiva, transaccional, con RLS y `GRANT` condicionales); **no edites** una ya aplicada (el runner rechaza cambios por SHA-256).
3. Reglas del proyecto:
   - Todo repositorio se usa con `orgId`; un endpoint nuevo lleva `@Perm(...)` y, si procede, `@Feature(...)`, y una prueba de aislamiento entre organizaciones en `security.spec.ts`.
   - Entradas con esquemas zod `.strict()`.
   - No inventes datos: lo desconocido es `unverified`/`n/a`, no un valor por defecto optimista.
   - Los secretos nunca entran en código, logs, respuestas ni auditoría (usa `redact`/`SecretBox`).
   - Una acción que cambie un sistema real necesita aprobación firmada y un ejecutor explícito; no añadas escrituras a un conector.
   - Documenta lo que **no** funciona o no se verificó: preferimos «implementado, sin validar» a una afirmación falsa.
4. Mensajes de commit descriptivos y pequeños. Añade pruebas con el cambio.
5. Seguridad: informa en privado (ver `SECURITY.md`).
