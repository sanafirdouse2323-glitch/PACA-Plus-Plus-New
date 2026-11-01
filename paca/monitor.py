"""PACA++ continuous-authorisation reference monitor.

One monitor sits at every stage boundary (tool selection, memory write, delegation,
tool call, egress). It never trusts model output: authority comes from a task-bound
capability, facts about data come from provenance labels, and every allowed effect gets
an HMAC token bound to the exact action + arguments that the executor must verify.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from .engine import PolicyEngine
from .obligations import ObligationRunner
from .parser import parse_policy_set
from .provenance import Arg, Label
from .runtime import ACTIONS, Capability, Decision, Request, Violation

CHECKS = {
    "C1":  ("Scope: action and target inside the task-bound capability", "capability escalation; goal hijack; cross-stage drift"),
    "C2":  ("Liveness: capability not expired, call budget not exhausted", "stale authority; cost/loop DoS"),
    "C3":  ("Manifest pin: tool hash/version matches what was authorised", "MCP poisoning; rug-pull; tool-selection hijack; supply chain"),
    "C4a": ("Untrusted-derived control value on destructive action", "goal hijack; confused deputy"),
    "C4b": ("Untrusted-derived control value on command execution", "indirect injection; structured-output injection; fragmentation"),
    "C4c": ("Untrusted-derived delegation target", "agent-to-agent injection"),
    "C4d": ("Untrusted-derived tool selection", "tool-selection hijack"),
    "C4e": ("Untrusted-derived settings change", "confused deputy"),
    "C4f": ("Untrusted recipient with non-public data", "indirect injection; exfiltration"),
    "C4g": ("Untrusted recipient, public data: human approval", "reply/forward workflows"),
    "C5":  ("Data sensitivity above destination clearance", "uncontrolled egress; sensitive-data extraction"),
    "C6":  ("Tenant boundary", "cross-tenant retrieval"),
    "C7":  ("Internal / metadata endpoint", "SSRF and network pivot"),
    "C8":  ("Fan-out limit: distinct recipients per task", "agent worm / propagation"),
    "C9":  ("Untrusted data into instruction memory", "memory poisoning; provenance laundering"),
    "C10a": ("Protected configuration written from untrusted data", "config tampering; CI/CD injection"),
    "C10b": ("Protected configuration needs human approval", "config tampering"),
    "C11": ("Delegated authority must be a subset of the parent's", "capability escalation; multi-agent confused deputy"),
    "C12": ("Quarantine after repeated denied attempts", "approval fatigue; autonomy loops"),
    "C13": ("Effect token binds executed effect to the authorised one", "planner/critic manipulation; TOCTOU argument swap"),
    "C15": ("Human gate on irreversible release actions", "prompt-to-commit manipulation"),
}

DEFAULT_CLEARANCE = {"corp.example": 3, "partner.example": 1, "storage.cloud.example": 0,
                     "chan:#finance": 2, "chan:#general": 0}
PROTECTED = ["*/.github/workflows/*", ".github/workflows/*", "*AGENTS.md", "*/.agent/*", "*/.git/*"]
INTERNAL_RE = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|metadata\.|.*\.internal$)")


def host_of(value: Any) -> str:
    v = str(value)
    if "://" in v:
        return (urlparse(v).hostname or "").lower()
    if "@" in v:
        return v.rsplit("@", 1)[1].lower()
    if v.startswith("#"):
        return "chan:" + v
    return v.lower()


def is_exact(pattern: str) -> bool:
    return not any(c in pattern for c in "*?[")


def match_grant(cap: Capability, action: str, target: str) -> Optional[str]:
    for pat in cap.grants.get(action, ()):
        if fnmatch.fnmatchcase(target, pat):
            return pat
    return None


class AuditLog:
    """Hash-chained, tamper-evident decision log."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []

    def append(self, rec: Dict[str, Any]) -> None:
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        body = json.dumps(rec, sort_keys=True, default=str)
        self.entries.append({**rec, "prev": prev, "hash": hashlib.sha256((prev + body).encode()).hexdigest()})

    def verify(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            rec = {k: v for k, v in e.items() if k not in ("prev", "hash")}
            h = hashlib.sha256((prev + json.dumps(rec, sort_keys=True, default=str)).encode()).hexdigest()
            if e["prev"] != prev or e["hash"] != h:
                return False
            prev = e["hash"]
        return True


class Monitor:
    name = "paca"
    tracks_labels = True

    def __init__(self, policy_text: Optional[str] = None, clearance: Optional[Dict[str, int]] = None,
                 protected: Optional[List[str]] = None, quarantine_after: int = 3,
                 disable: Iterable[str] = (), key: Optional[bytes] = None) -> None:
        if policy_text is None:
            here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            with open(os.path.join(here, "examples", "agent_policy.paca"), encoding="utf-8") as fh:
                policy_text = fh.read()
        self.rules = parse_policy_set(policy_text, "agent_policy", default_decision="permit")
        self.engine = PolicyEngine("deny_overrides", default_decision="permit")
        self.clearance = dict(DEFAULT_CLEARANCE if clearance is None else clearance)
        self.protected = list(PROTECTED if protected is None else protected)
        self.quarantine_after, self.disable = quarantine_after, set(disable)
        self.key = key or os.urandom(32)
        self.audit = AuditLog()
        self.obligations = ObligationRunner()
        self.obligations.register("audit_log", lambda **kw: None)   # audit is always written below
        self.strikes: Dict[str, int] = {}
        self.dests: Dict[str, set] = {}

    # ---------------------------------------------------------------- helpers
    def _clearance(self, host: str, trusted_literal: bool) -> int:
        best, n = None, -1
        for suffix, c in self.clearance.items():
            if (host == suffix or host.endswith("." + suffix)) and len(suffix) > n:
                best, n = c, len(suffix)
        if best is not None:
            return best
        return 1 if trusted_literal and not host.startswith("chan:") else 0

    def _context(self, req: Request, spec: Dict[str, Any], matched_pat: Optional[str]) -> Dict[str, Any]:
        args, cap = req.args, req.cap
        tgt = args.get(spec["target"])
        control_names = [spec["target"]] + spec.get("control", [])
        untrusted_control = False
        for n in control_names:
            a = args.get(n)
            if a is None or a.label.integrity != "untrusted":
                continue
            if n == spec["target"] and matched_pat is not None and is_exact(matched_pat):
                continue          # the exact, human-granted literal is the authority, not the argument's provenance
            untrusted_control = True
        pay = [args[n] for n in spec.get("payload", []) if n in args]
        pl = Label.join(*(a.label for a in pay)) if pay else Label()
        is_egress = spec["cls"] == "egress" and (req.action != "fetch_url" or bool(pay))
        host = host_of(tgt.value) if tgt is not None else ""
        trusted_dest = tgt is not None and tgt.label.integrity == "trusted"
        clr = self._clearance(host, trusted_dest) if is_egress else 99
        url_like = req.action in ("fetch_url", "http_post")
        value = str(tgt.value) if tgt is not None else ""
        scope = "core" if (req.action == "mem_write" and value.startswith("core/")) else ""
        cross = bool(pl.tenant and pl.tenant != cap.tenant) or bool(
            req.resource is not None and req.resource.tenant and req.resource.tenant != cap.tenant)
        return {
            "action": {"name": req.action, "cls": spec["cls"]},
            "dest": {"host": host, "clearance": clr, "internal": bool(url_like and INTERNAL_RE.match(host)),
                     "trusted": trusted_dest},
            "flow": {"max_sens": pl.sensitivity, "excess": (pl.sensitivity - clr) if is_egress else -9,
                     "cross_tenant": cross},
            "control": {"integrity": "untrusted" if untrusted_control else "trusted"},
            "payload": {"integrity": pl.integrity, "sensitivity": pl.sensitivity},
            "target": {"scope": scope, "protected": any(fnmatch.fnmatchcase(value, p) for p in self.protected)
                       if req.action in ("write_file", "delete_file") else False},
            "cap": {"principal": cap.principal, "task": cap.task_id},
        }, is_egress, host

    # ---------------------------------------------------------------- decision
    def decide(self, req: Request) -> Decision:
        if req.action not in ACTIONS:          # fail closed on anything the monitor does not model
            return Decision("deny", [Violation("C1", "deny", f"unknown action {req.action!r}")], req.digest)
        spec, cap, v = ACTIONS[req.action], req.cap, []
        tgt = req.args.get(spec["target"])
        tval = str(tgt.value) if tgt is not None else ""
        consequential = spec["cls"] != "read"

        if consequential and self.strikes.get(cap.task_id, 0) >= self.quarantine_after:
            v.append(Violation("C12", "deny", "task quarantined after repeated denied/escalated attempts"))
        pat = match_grant(cap, req.action, tval)
        if req.action not in cap.grants:
            v.append(Violation("C1", "deny", f"{req.action} not granted for this task"))
        elif pat is None:
            v.append(Violation("C1", "deny", f"target {tval!r} outside granted scope {list(cap.grants[req.action])}"))
        if req.step > cap.expires:
            v.append(Violation("C2", "deny", f"capability expired at step {cap.expires} (now {req.step})"))
        elif cap.calls >= cap.max_calls:
            v.append(Violation("C2", "deny", f"call budget {cap.max_calls} exhausted"))
        if req.tool is not None:
            pinned = cap.tool_pins.get(req.tool.name)
            if pinned is None:
                v.append(Violation("C3", "deny", f"tool {req.tool.name!r} was never authorised for this task"))
            elif pinned != req.tool.hash:
                v.append(Violation("C3", "deny", f"manifest of {req.tool.name!r} changed after authorisation (v{req.tool.version})"))
        if req.action == "delegate":
            child = req.args["child_grants"].value
            for act, pats in child.items():
                parent = cap.grants.get(act)
                if parent is None or not all(any(p == q or fnmatch.fnmatchcase(p, q) for q in parent) for p in pats):
                    v.append(Violation("C11", "deny", f"child grant {act}:{list(pats)} exceeds parent authority"))
                    break

        ctx, is_egress, host = self._context(req, spec, pat)
        if is_egress:
            seen = self.dests.setdefault(cap.task_id, set())
            if tval not in seen and len(seen) >= cap.max_fanout:
                v.append(Violation("C8", "deny", f"fan-out limit {cap.max_fanout} reached"))
        res = self.engine.evaluate_set(self.rules, ctx, action=req.action)
        obl = sorted({o for n, os_ in res.obligation_map.items() for o in os_})
        for effect, name in res.fired:
            note = next((p.metadata.get("note", "") for p in self.rules if p.name == name), "")
            if effect == "deny":
                v.append(Violation(name, "deny", note or "policy rule"))
            elif "require_approval" in res.obligation_map.get(name, []):
                v.append(Violation(name, "escalate", note or "human approval required"))

        v = [x for x in v if x.check not in self.disable]
        if any(x.severity == "deny" for x in v):
            verdict = "deny"
        elif any(x.severity == "escalate" for x in v):
            verdict = "allow" if req.approval == req.digest else "needs_approval"
        else:
            verdict = "allow"

        d = Decision(verdict, v, req.digest, None, self.obligations.run(obl, req=req))
        if verdict == "allow":
            cap.calls += 1
            if is_egress:
                self.dests.setdefault(cap.task_id, set()).add(tval)
            d.token = hmac.new(self.key, req.digest.encode(), hashlib.sha256).hexdigest()
        elif consequential:
            self.strikes[cap.task_id] = self.strikes.get(cap.task_id, 0) + 1
        self.audit.append({"step": req.step, "task": cap.task_id, "action": req.action, "verdict": verdict,
                           "checks": d.checks, "digest": req.digest[:16], "principal": cap.principal})
        return d

    def verify(self, req: Request, d: Decision) -> bool:
        """Executor-side check (C13): the effect about to run must match the authorised digest."""
        if d.verdict != "allow" or d.token is None:
            return False
        if "C13" in self.disable:        # ablation switch
            return True
        want = hmac.new(self.key, req.digest.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, d.token)

    def scan(self, source: str, text: str, style: Optional[str]) -> bool:
        return False            # PACA++ does not rely on content classification

    def issue(self, cap: Capability) -> Capability:
        return cap


__all__ = ["Monitor", "AuditLog", "CHECKS", "host_of", "match_grant"]
