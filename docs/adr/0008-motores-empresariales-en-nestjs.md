# ADR-0008 — Motores empresariales en el plano de control NestJS

Fecha: 2026-11-16 · Estado: propuesta (pendiente de aprobación humana)

## Contexto
El encargo asumía Python/FastAPI como backend principal y NestJS como servicio auxiliar. El repositorio es lo contrario: NestJS es el plano de control (autenticación, tenancy, orquestación, aprobaciones, auditoría) y FastAPI solo ofrece analítica determinista con un *fallback* idéntico en TypeScript.

## Decisión
Implementar CTEM, IAM, correlación, SOAR, conectores, casos, informes y privacidad **una sola vez, en NestJS**. Python conserva su rol de analítica. No se duplica lógica ni se crea un segundo almacén.

## Consecuencias
- (+) Un único modelo de autorización, auditoría y multi-tenant (repositorios con `orgId` + RLS); un solo despliegue de lógica.
- (+) No se reemplazan tecnologías funcionales.
- (−) El motor de grafos y la correlación viven en proceso Node; a gran escala convendrá moverlos a SQL/servicio dedicado (`ROADMAP.md`).
- (−) Los modelos de datos con IA/estadística (futuros) podrían encajar mejor en Python: se expondrían por el contrato de analítica ya existente.

## Alternativas descartadas
Reescribir el control plane en FastAPI (riesgo alto, sin ganancia funcional); duplicar los motores en ambos servicios (dos fuentes de verdad).
