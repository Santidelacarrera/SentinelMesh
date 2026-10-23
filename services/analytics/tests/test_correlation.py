import logging
import re

from fastapi.testclient import TestClient

from app.correlation import CorrelationLogFilter, from_headers, propagation_headers
from app.main import app

c = TestClient(app)
TP = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def test_valid_id_is_echoed_and_missing_or_malformed_is_replaced():
    sent = {"x-request-id": "req-from-gw-0001"}
    assert c.get("/healthz", headers=sent).headers["x-request-id"] == "req-from-gw-0001"
    minted = c.get("/healthz").headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f-]{36}", minted)
    for bad in ("short", "has space in it", 'inj"ected', "a" * 200):
        assert c.get("/healthz", headers={"x-request-id": bad}).headers["x-request-id"] != bad


def test_only_the_allowlist_survives_and_values_are_validated():
    h = from_headers(
        {
            "x-request-id": "req-1234abcd",
            "x-tenant": "org_acme",
            "traceparent": TP,
            "authorization": "Bearer s",
            "cookie": "a=b",
        }
    )
    assert set(h) == {"x-request-id", "x-tenant", "traceparent"}
    assert "x-tenant" not in from_headers({"x-tenant": "bad tenant!"})
    assert "traceparent" not in from_headers({"traceparent": "garbage"})


def test_context_is_per_request_and_cleared_afterwards():
    assert propagation_headers() == {}
    c.post("/v1/forensics/summary", json={"evidence": []}, headers={"x-request-id": "req-1234abcd"})
    assert propagation_headers() == {}  # nothing leaks out of the request


def test_log_records_carry_request_id_and_tenant():
    records = []

    class Grab(logging.Handler):
        def emit(self, record):
            records.append(record)

    log = logging.getLogger("probe")
    log.addFilter(CorrelationLogFilter())
    log.addHandler(Grab())
    log.setLevel(logging.INFO)

    @app.get("/_probe")
    def probe():
        log.info("inside request")
        return {"ok": True}

    c.get("/_probe", headers={"x-request-id": "req-1234abcd", "x-tenant": "org_acme"})
    assert records[-1].request_id == "req-1234abcd" and records[-1].tenant == "org_acme"
