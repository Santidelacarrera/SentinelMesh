# Análisis competitivo (orientativo, sin pruebas comparables)

**Límites del análisis.** No se hizo una evaluación práctica de ningún producto ni se consultó documentación actualizada durante este trabajo: las columnas de competidores recogen **categorías de capacidad que los fabricantes anuncian en general** (Wiz, Tenable One, Rapid7, Microsoft Defender, CrowdStrike Falcon, Palo Alto Cortex, Qualys) y están marcadas como *pendiente de validación*. **No se afirma que SentinelMesh supere a ninguno**: no existen pruebas comparables y reproducibles. No se copió código, interfaces ni documentación privada.

## Matriz de funcionalidades de SentinelMesh (estado real en este repositorio)
Leyenda: **Disponible** (implementado y probado automáticamente) · **Parcial** · **No disponible** · **Pendiente de validación** (implementado, sin verificar contra el entorno real).

| Capacidad | SentinelMesh | Observaciones |
|---|---|---|
| Descubrimiento de activos | Parcial | inventario + conectores (Wazuh/CrowdStrike/Defender/AWS/Azure/GCP): **pendiente de validación** real; sin descubrimiento activo de red propio (por diseño: solo activos verificados) |
| Attack Surface Management | Parcial | exposiciones con evidencia/historial y sonda TLS autorizada; sin escáner de puertos/DNS integrado, depende de observaciones externas |
| Gestión de vulnerabilidades | Disponible | NVD/KEV/EPSS por importación, estados, SLA; **sin escáner propio** (ingesta Trivy/SARIF/ZAP/Semgrep) |
| Prioridad contextual | Disponible | explicable; pesos heurísticos, no calibrados con datos |
| Attack path analysis | Parcial | grafo sobre relaciones registradas; teórico; calidad depende de la completitud del inventario |
| IAM / identidades | Parcial | higiene y riesgos con datos de IdP (pendiente de validación); sin CIEM completo ni análisis de permisos efectivos cloud |
| SOAR | Parcial | playbooks, niveles, aprobación firmada, kill switch; **solo ejecutor de laboratorio** (no actúa sobre sistemas reales) |
| Correlación multi-fuente | Parcial | reglas por atributos compartidos con confianza; sin ML ni cobertura de miles de reglas |
| Gestión de incidentes y evidencia | Disponible | cadena de custodia, exportación; admisibilidad legal no evaluada |
| Multi-tenant / MSSP | Disponible | RLS verificada en PostgreSQL real; panel de plataforma por API (sin UI de plataforma) |
| Informes PDF | Disponible | 4 tipos; diseño sobrio, sin plantillas de marca |
| Integraciones | Pendiente de validación | 9 conectores, todos probados contra mocks de protocolo |
| Automatización / IA | Parcial | asistente determinista con fuentes; LLM externo opt-in |
| Experiencia de usuario | Parcial | consola funcional en español; sin pruebas de usabilidad ni de accesibilidad formales |
| Agente/sensor propio, EDR, escaneo cloud agentless | No disponible | diferencia de categoría frente a Falcon/Defender/Wiz |

## Dónde podría diferenciarse (hipótesis a validar)
1. **Honestidad verificable**: cada hallazgo declara su confianza y fuente; nada «confirmado» sin evidencia; el estado de cada integración es el real.
2. **Aprobación humana criptográficamente ligada a la acción exacta** y modo AUTOMATED apagado por defecto con kill switch.
3. **Autoalojable y multi-tenant** con aislamiento verificable (RLS), útil para MSSP y entornos regulados.
4. **Neutralidad de proveedor**: correlaciona EDR/SIEM/IdP/cloud de varios fabricantes en vez de uno.
5. **Prioridad explicable** que se puede discutir factor a factor.

## Carencias frente al mercado (a priorizar si se quiere competir)
Sensores/agentes propios, cobertura cloud profunda (agentless scanning, CSPM/CIEM), base de reglas y de inteligencia mantenida por un equipo, ejecutores de respuesta reales con RBAC de escritura, SLA, certificaciones, escala probada (ver `TESTING.md`) y UX validada con usuarios.
