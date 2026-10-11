# Matriz de comunicación (generada)

Todo lo que no está en esta tabla está **denegado** (AuthorizationPolicy default-deny + NetworkPolicy default-deny).

| Origen (identidad SPIFFE) | Destino | Métodos | Rutas |
|---|---|---|---|
| **gateway (Internet, con JWT)** | shadowapi-guard:8080 | todos | todas |
| shadowapi-guard | contextrag-engine:8080 | POST | /v1/query, /v1/embed |
| **gateway (Internet, con JWT)** | sentinelmesh-api:3000 | GET, HEAD, POST, PUT, PATCH, DELETE | /api/v1/*, /healthz |
| shadowapi-guard | sentinelmesh-api:3000 | POST | /api/v1/incidents/trigger |
| sentinelmesh-api | sentinelmesh-analytics:8000 | POST, GET | /v1/*, /healthz |
| **gateway (Internet, con JWT)** | sentinelmesh-web:80 | GET, HEAD | todas |
