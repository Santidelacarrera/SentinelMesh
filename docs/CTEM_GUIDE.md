# Guía CTEM

Ciclo: **descubrir → validar alcance → evaluar → priorizar → movilizar** (SOAR) → medir (dashboard/informes).

## 1. Activos
`POST /inventory/assets` (o conectores). Tipos: dominio, subdominio, IP, servidor, web_app, api, contenedor, clúster k8s, servicio cloud, repositorio, base de datos, endpoint. Cada activo guarda fuente, primera/última observación, estado (`active/stale/retired`), criticidad, propietario, exposición a Internet, controles compensatorios, etiquetas y propiedad. El identificador es único por organización (sin distinguir mayúsculas) y se registra el historial.

**Relaciones** (`POST /inventory/relations`) alimentan la prioridad y las rutas: `runs_on, depends_on, hosts, trusts, member_of, authenticates_to, stores_data_in, can_assume, admin_of, has_access, exposes`, con `confidence` (0–1) y evidencia.

### Propiedad y alcance (no se escanea nada ajeno)
1. `…/ownership/challenge` devuelve un TXT `_sentinelmesh.<dominio>` = `sentinelmesh-verify=…`.
2. `…/ownership/verify {method:"dns_txt"}` lo comprueba; `manual_attestation` exige una nota (≥10 caracteres) y queda auditada.
3. `…/scope {inScope:true}` solo se permite con propiedad verificada.
4. Las comprobaciones **activas** (`…/tls-check`) solo corren sobre activos verificados **y** en alcance, y rechazan direcciones privadas salvo `TLS_PROBE_ALLOW_PRIVATE=1`. La sonda TLS **inspecciona** el certificado (`rejectUnauthorized:false` a propósito, para poder informar de certificados inválidos); no envía datos.

## 2. Vulnerabilidades
`POST /vulns`. Reglas: nunca se inventa una puntuación; sin `severity`, `cvss` ni CVE importado se rechaza. Estados `open, in_progress, mitigated, resolved, accepted` (aceptar riesgo exige justificación). Confianza `confirmed | suspected | unverified`. Plazo por SLA (crítica 7 d, alta 30, media 90, baja 180) o fecha KEV si es anterior.

**Inteligencia**: `POST /intel/import {kind: nvd|kev|epss, payload}` acepta el JSON de NVD 2.0, el catálogo KEV de CISA o EPSS (JSON o CSV). El operador descarga los feeds; SentinelMesh no los baja solo. Al importar se reprioriza.

## 3. Exposición (superficie de ataque)
`POST /exposures/observe` registra lo que vio un escáner **autorizado**. Control de falsos positivos: la primera observación es `suspected`; la segunda (o una `confirmed` explícita) la confirma; un escaneo `complete` con `coverKinds` cierra lo que ya no aparece. Hay historial (`/exposures/history`) y detección de activos olvidados (`/inventory/assets/stale-check`).

## 4. Rutas de ataque
`GET /ctem/attack-paths`: entrada = activos expuestos a Internet; destino = críticos. Cada ruta muestra nodos, aristas con confianza, privilegios implicados, impacto, evidencia y notas. Estado **`theoretical`** (hipótesis) o **`corroborated`** (hay alertas en algún nodo); jamás «intrusión confirmada». Sin vulnerabilidad/exposición en el punto de entrada, la confianza cae (foothold hipotético).

## 5. Prioridad (explicable)
`prioritize()` suma factores con nombre y razón: severidad base (CVSS×3.6, o la declarada), KEV (+25), EPSS (+3/+8/+15), criticidad del activo (0–15), exposición externa (+10), entorno dev (−10), controles compensatorios (−5 c/u, máx −15), privilegios alcanzables (+5 c/u, máx 10), radio de impacto (+5), exposición confirmada (+5), y escala por confianza (×1/×0,7/×0,4). Niveles: inmediata ≥75, alta ≥55, media ≥35, baja ≥15. **Regla de anulación**: KEV + Internet + confirmada ⇒ siempre *inmediata*. La explicación indica los 3 factores principales y lo que redujo la puntuación. Los pesos son una decisión de producto documentada en `ctem/priority.ts`, no un modelo estadístico.
