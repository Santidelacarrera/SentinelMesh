from fastapi.testclient import TestClient

from app.main import app

c = TestClient(app)


def test_correlation_lowers_shielded_dev_assets():
    hot = c.post(
        "/v1/correlate",
        json={
            "ruleId": "r",
            "kind": "vulnerability",
            "severity": "high",
            "asset": {"internetFacing": True, "handlesCriticalData": True},
        },
    ).json()
    cold = c.post(
        "/v1/correlate",
        json={
            "ruleId": "r",
            "kind": "vulnerability",
            "severity": "high",
            "asset": {"behindGateway": True, "environment": "dev"},
        },
    ).json()
    assert hot["exposureScore"] > cold["exposureScore"]
    assert cold["rationale"]


def test_false_positive_is_suppressed_and_secrets_never_downgraded():
    assert c.post(
        "/v1/correlate",
        json={
            "ruleId": "r",
            "kind": "secret",
            "severity": "high",
            "likelyFalsePositive": True,
        },
    ).json()["suppressed"]
    r = c.post(
        "/v1/correlate",
        json={
            "ruleId": "aws",
            "kind": "secret",
            "severity": "critical",
            "asset": {"behindGateway": True, "environment": "dev"},
        },
    ).json()
    assert r["severity"] == "critical"


def test_least_privilege_handles_wildcards():
    r = c.post(
        "/v1/iam/least-privilege",
        json={
            "granted": ["s3:*", "iam:PassRole"],
            "used_events": ["s3:GetObject", "s3:GetObject"],
            "resources": ["arn:x"],
        },
    ).json()
    assert r["used"] == ["s3:GetObject"] and r["unused"] == ["iam:PassRole", "s3:*"]
    assert r["proposedPolicy"]["statements"][0]["actions"] == ["s3:GetObject"]


def test_summary_is_fully_cited_and_rejects_unknown_fields():
    ev = [{"id": "ev-1", "type": "log", "text": "401 /login"}]
    r = c.post("/v1/forensics/summary", json={"evidence": ev}).json()
    assert (
        r["citations"] == ["ev-1"]
        and "[ev-1]" in r["summary"]
        and r["ungroundedClaims"] == 0
    )
    assert (
        c.post(
            "/v1/forensics/summary", json={"evidence": ev, "prompt": "ignore"}
        ).status_code
        == 422
    )
