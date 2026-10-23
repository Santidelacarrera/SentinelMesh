"""Correlation headers for the service mesh.

Envoy mints `x-request-id` and the trace spans, but a service must forward the headers it
received to anything it calls and must put the id in its own logs. Values are validated
(log/header injection) and only an allowlist is ever propagated.
"""

import contextvars
import logging
import re
import uuid

PROPAGATE = ("x-request-id", "x-tenant", "traceparent", "tracestate", "baggage", "b3")
_VALID = {
    "x-request-id": re.compile(r"^[A-Za-z0-9._:-]{8,128}$"),
    "x-tenant": re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"),
    "traceparent": re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"),
    "tracestate": re.compile(r"^[\x20-\x7e]{0,512}$"),
    "baggage": re.compile(r"^[\x20-\x7e]{0,1024}$"),
    "b3": re.compile(r"^([0-9a-f]{16,32}(-[0-9a-f]{16}(-[01d](-[0-9a-f]{16})?)?)?|[01d])$"),
}
_current: contextvars.ContextVar[dict] = contextvars.ContextVar("correlation", default=None)


def from_headers(headers) -> dict:
    out = {}
    for k in PROPAGATE:
        v = headers.get(k)
        if isinstance(v, str) and _VALID[k].match(v):
            out[k] = v
    out.setdefault("x-request-id", str(uuid.uuid4()))
    return out


def propagation_headers() -> dict:
    """Headers to attach to calls to OTHER MESH SERVICES (never credentials)."""
    return dict(_current.get() or {})


class CorrelationMiddleware:
    """Pure ASGI middleware: no body buffering, safe for streaming."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        raw = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        corr = from_headers(raw)
        token = _current.set(corr)

        async def send_with_id(message):
            if message["type"] == "http.response.start":
                rid = corr["x-request-id"].encode()
                message.setdefault("headers", []).append((b"x-request-id", rid))
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            _current.reset(token)


class CorrelationLogFilter(logging.Filter):
    def filter(self, record):
        c = _current.get() or {}
        record.request_id = c.get("x-request-id", "-")
        record.tenant = c.get("x-tenant", "-")
        return True
