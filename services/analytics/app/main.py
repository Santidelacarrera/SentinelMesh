"""SentinelMesh analytics: deterministic, explainable context for findings, IAM and forensics.

No generative model is used to *state* facts: every output is derived from the input and
carries its rationale / citations, so there is nothing to hallucinate.
"""
from typing import Literal, Optional
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from .correlation import CorrelationMiddleware

app = FastAPI(title="SentinelMesh Analytics", version="0.1.0")
app.add_middleware(CorrelationMiddleware)
Severity = Literal["critical", "high", "medium", "low", "info"]
ORDER = ["info", "low", "medium", "high", "critical"]
BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Asset(BaseModel):
    model_config = ConfigDict(extra="ignore")
    internetFacing: bool = False
    behindGateway: bool = False
    handlesCriticalData: bool = False
    environment: Literal["prod", "staging", "dev"] = "prod"


class CorrelateIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ruleId: str
    kind: Literal["vulnerability", "secret"]
    severity: Severity
    likelyFalsePositive: bool = False
    asset: Optional[Asset] = None


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/v1/correlate")
def correlate(i: CorrelateIn):
    if i.likelyFalsePositive:
        return {"severity": "info", "exposureScore": 0, "suppressed": True,
                "suppressionReason": "likely false positive (test/fixture/placeholder)",
                "rationale": ["matched false-positive heuristics"]}
    score, why = BASE[i.severity], []
    a = i.asset
    if a is None:
        why.append("no asset context: severity kept as reported (conservative)")
    else:
        score += 15 if a.internetFacing else -15
        why.append("asset is internet-facing (+15)" if a.internetFacing else "asset not internet-facing (-15)")
        if a.behindGateway:
            score -= 10; why.append("protected by API gateway (-10)")
        if a.handlesCriticalData:
            score += 10; why.append("asset handles critical data (+10)")
        if a.environment == "dev":
            score -= 20; why.append("dev environment (-20)")
    score = max(0, min(100, score))
    sev = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low" if score >= 15 else "info"
    if i.kind == "secret" and ORDER.index(sev) < ORDER.index(i.severity):
        sev = i.severity  # a leaked secret is live regardless of where it was found
    return {"severity": sev, "exposureScore": score, "suppressed": False, "rationale": why}


class LeastPrivIn(Strict):
    granted: list[str] = Field(min_length=1, max_length=2000)
    used_events: list[str] = Field(max_length=100000)
    resources: list[str] = ["*"]


def _covers(grant: str, action: str) -> bool:
    return grant == action or (grant.endswith("*") and action.startswith(grant[:-1]))


@app.post("/v1/iam/least-privilege")
def least_privilege(i: LeastPrivIn):
    used = sorted({a for a in i.used_events if any(_covers(g, a) for g in i.granted)})
    unused = sorted(g for g in i.granted if g not in used)
    return {"granted": i.granted, "used": used, "unused": unused,
            "usageRatio": len(used) / len(i.granted),
            "proposedPolicy": {"version": "2012-10-17",
                               "statements": [{"effect": "Allow", "actions": used, "resources": i.resources}] if used else []}}


class Evidence(Strict):
    id: str
    type: str
    text: str


class SummaryIn(Strict):
    evidence: list[Evidence] = Field(max_length=2000)


@app.post("/v1/forensics/summary")
def summary(i: SummaryIn):
    """Grounded summary: one line per evidence item, each citing its id. Nothing is inferred beyond the evidence."""
    if not i.evidence:
        return {"summary": "No evidence was captured; no conclusions can be drawn.", "citations": [], "ungroundedClaims": 0}
    lines = [f"- [{e.id}] {e.type}: {e.text}" for e in i.evidence]
    return {"summary": "\n".join(lines), "citations": [e.id for e in i.evidence], "ungroundedClaims": 0}
