# ADR-0004 · Multitenencia: `orgId` obligatorio + RLS
- **Fecha:** 2026-10-13 · **Estado:** aceptada

**Decisión.** Toda lectura/escritura del almacén exige `orgId` (un handler no puede tocar filas de otro tenant) y los identificadores ajenos responden 404. En PostgreSQL, además, **RLS forzada** por `app.org_id` y un rol de aplicación sin `BYPASSRLS`, sin `DELETE`; la traza de auditoría y las versiones de workflow son **append-only** por trigger.

**Consecuencias.** Pruebas: otra organización o ninguna ve 0 filas, inserción cruzada rechazada, borrado/actualización de tablas inmutables rechazados.
