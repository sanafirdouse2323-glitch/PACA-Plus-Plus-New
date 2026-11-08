"""Local reference decision API for PACA++; it never executes side effects."""
from __future__ import annotations

import hashlib
import json
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from paca.monitor import Monitor
from paca.provenance import Arg, Label
from paca.runtime import Capability, Request


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CapabilityInput(StrictModel):
    """Caller-supplied demo authority; not a trusted production credential."""

    id: str = Field(min_length=1, max_length=200)
    principal: str = Field(min_length=1, max_length=200)
    tenant: str = Field(min_length=1, max_length=200)
    task: str = Field(min_length=1, max_length=200)
    role: str = Field(min_length=1, max_length=100)
    grants: dict[str, list[str]]
    expires: int = Field(ge=1)  # PACA monitor step limit, not wall-clock expiry.
    max_calls: int = Field(default=40, ge=1)
    max_fanout: int = Field(default=5, ge=1)


class DecisionInput(StrictModel):
    action: str = Field(min_length=1, max_length=100)
    args: dict[str, Any] = Field(default_factory=dict)
    capability: CapabilityInput
    step: int = Field(default=1, ge=1)


app = FastAPI(
    title="PACA++ Reference Decision API",
    version="0.3.1",
    description=(
        "Local demonstration decision API only. It does not execute tools or "
        "external side effects and is not a production authorization boundary."
    ),
)
monitor = Monitor()
_monitor_lock = Lock()
_capability_lock = Lock()
_capabilities: dict[tuple[str, str, str], tuple[str, Capability]] = {}


def _get_capability(data: CapabilityInput) -> Capability:
    grants = {name: tuple(sorted(set(items))) for name, items in data.grants.items()}
    identity = {
        "principal": data.principal,
        "tenant": data.tenant,
        "task": data.task,
        "role": data.role,
        "grants": {name: list(items) for name, items in sorted(grants.items())},
        "expires": data.expires,
        "max_calls": data.max_calls,
        "max_fanout": data.max_fanout,
    }
    fingerprint = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    key = (data.principal, data.tenant, data.id)
    with _capability_lock:
        previous = _capabilities.get(key)
        if previous:
            old_fingerprint, capability = previous
            if old_fingerprint != fingerprint:
                raise HTTPException(409, "capability authority cannot change for an active id")
            return capability
        task_identity = json.dumps(
            [data.principal, data.tenant, data.task], separators=(",", ":")
        ).encode()
        task_id = "reference:" + hashlib.sha256(task_identity).hexdigest()
        capability = Capability(
            data.id, data.principal, data.tenant, task_id, data.role,
            grants=grants, expires=data.expires,
            max_calls=data.max_calls, max_fanout=data.max_fanout,
        )
        _capabilities[key] = (fingerprint, capability)
        return capability


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "paca-reference-decision-api"}


@app.post("/decide")
def decide(payload: DecisionInput) -> dict[str, Any]:
    """Evaluate a decision; every caller argument is treated as untrusted."""
    capability = _get_capability(payload.capability)
    label = Label(
        integrity="untrusted",
        sensitivity=3,
        tenant=payload.capability.tenant,
        origins=frozenset({"paca_reference_api_input"}),
    )
    args = {name: Arg(value, label) for name, value in payload.args.items()}
    request = Request(payload.action, args, capability, step=payload.step)
    # One lock covers mutable monitor counters and single-use token verification.
    with _monitor_lock:
        decision = monitor.decide(request)
        token_verified = (
            monitor.verify(request, decision) if decision.verdict == "allow" else False
        )
    return {
        "verdict": decision.verdict,
        "checks": decision.checks,
        "violations": [
            {"check": item.check, "severity": item.severity, "message": item.msg}
            for item in decision.violations
        ],
        "digest": decision.digest,
        "obligations": decision.obligations,
        "reference_token_verified": token_verified,
        "effect_executed": False,
    }
