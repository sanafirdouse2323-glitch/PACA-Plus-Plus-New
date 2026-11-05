"""PACA++ reference monitor used by the deterministic simulator.

The simulator routes selected effect requests through this monitor. It does not itself
mediate real agent planning, inbound communication, connector I/O, or production effects.
Every allowed request receives a single-use token bound to its arguments for an executor
integration to verify.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import hmac
import json
import os
import posixpath
import re
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse
from importlib import resources

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
    "C4c": ("Untrusted delegated grant set", "agent-to-agent injection"),
    "C4d": ("Untrusted-derived tool selection", "tool-selection hijack"),
    "C4e": ("Untrusted setting value", "confused deputy"),
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
PATH_ACTIONS = frozenset({"read_file", "write_file", "delete_file"})


def canonical_path_target(value: Any) -> Optional[str]:
    """Return a lexically safe absolute POSIX path, or None for an invalid path.

    This rejects traversal and platform-separator ambiguity. A real executor must still
    resolve symlinks safely beneath an authorised directory and prevent TOCTOU races.
    """
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    if ".." in value.split("/"):
        return None
    normalized = posixpath.normpath(value)
    if not normalized.startswith("/") or normalized.startswith("//"):
        return None
    return normalized


def _canonical_path_pattern(pattern: Any) -> Optional[str]:
    if not isinstance(pattern, str) or not pattern or "\x00" in pattern or "\\" in pattern:
        return None
    if not pattern.startswith("/") or pattern.startswith("//") or ".." in pattern.split("/"):
        return None
    normalized = posixpath.normpath(pattern)
    if not normalized.startswith("/") or normalized.startswith("//"):
        return None
    return normalized


def host_of(value: Any) -> str:
    v = str(value).strip()
    if "://" in v:
        try:
            host = urlparse(v).hostname
        except ValueError:
            return ""
        return (host or "").lower().rstrip(".")
    if "@" in v:
        return v.rsplit("@", 1)[1].lower().rstrip(".")
    if v.startswith("#"):
        return "chan:" + v
    return v.lower().rstrip(".")


def is_internal_host(host: str) -> bool:
    """Conservatively identify local, private, link-local and reserved destinations."""
    normalized = (host or "").strip().lower().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized.split("%", 1)[0])
        return not address.is_global
    except ValueError:
        return (
            normalized == "localhost"
            or normalized.endswith(".localhost")
            or normalized.endswith(".local")
            or normalized == "metadata"
            or normalized.startswith("metadata.")
            or normalized.endswith(".internal")
            or bool(INTERNAL_RE.match(normalized))
        )


def is_allowed_network_host(host: str, allowed_domains: Iterable[str]) -> bool:
    """Match a domain exactly or on a DNS-label boundary."""
    normalized = (host or "").strip().lower().rstrip(".")
    if not normalized:
        return False
    domains = {(domain or "").strip().lower().rstrip(".") for domain in allowed_domains}
    return any(domain and (normalized == domain or normalized.endswith("." + domain))
               for domain in domains)


def _grant_is_subset(child: str, parent: str) -> bool:
    """Conservative glob-subset check; reject uncertain pattern-to-pattern relations."""
    if not isinstance(child, str) or not isinstance(parent, str):
        return False
    if ".." in child.split("/") or ".." in parent.split("/"):
        return False
    if child == parent:
        return True
    if is_exact(child):
        return fnmatch.fnmatchcase(child, parent)
    if parent.endswith("*") and parent.count("*") == 1 and "?" not in parent and "[" not in parent:
        return child.startswith(parent[:-1])
    return False


def is_exact(pattern: str) -> bool:
    return not any(c in pattern for c in "*?[")


def match_grant(cap: Capability, action: str, target: str) -> Optional[str]:
    """Match only canonical targets; filesystem paths reject traversal before globbing."""
    if action in PATH_ACTIONS:
        target = canonical_path_target(target)
        if target is None:
            return None
        for pattern in cap.grants.get(action, ()):
            safe_pattern = _canonical_path_pattern(pattern)
            if safe_pattern is not None and fnmatch.fnmatchcase(target, safe_pattern):
                return safe_pattern
        return None
    for pattern in cap.grants.get(action, ()):
        if isinstance(pattern, str) and fnmatch.fnmatchcase(target, pattern):
            return pattern
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
        try:
            for entry in self.entries:
                rec = {key: value for key, value in entry.items() if key not in ("prev", "hash")}
                h = hashlib.sha256((prev + json.dumps(rec, sort_keys=True, default=str)).encode()).hexdigest()
                if entry.get("prev") != prev or entry.get("hash") != h:
                    return False
                prev = entry["hash"]
            return True
        except (KeyError, TypeError, ValueError):
            return False


class Monitor:
    name = "paca"
    tracks_labels = True

    def __init__(self, policy_text: Optional[str] = None, clearance: Optional[Dict[str, int]] = None,
                 protected: Optional[List[str]] = None, quarantine_after: int = 3,
                 disable: Iterable[str] = (), key: Optional[bytes] = None,
                 approval_verifier: Optional[Callable[[Request, str], bool]] = None) -> None:
        if policy_text is None:
            policy_text = resources.files("paca").joinpath("policies", "agent_policy.paca").read_text(encoding="utf-8")
        self.rules = parse_policy_set(policy_text, "agent_policy", default_decision="permit")
        self.engine = PolicyEngine("deny_overrides", default_decision="permit")
        self.clearance = dict(DEFAULT_CLEARANCE if clearance is None else clearance)
        self.protected = list(PROTECTED if protected is None else protected)
        self.quarantine_after, self.disable = quarantine_after, set(disable)
        self.key = key or os.urandom(32)
        self.approval_verifier = approval_verifier
        self._issued_tokens: Dict[str, str] = {}
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
        # Unknown destinations are not automatically cleared merely because a literal was user-supplied.
        return 0

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
        raw_value = tgt.value if tgt is not None else ""
        value = (canonical_path_target(raw_value) or "") if req.action in PATH_ACTIONS else str(raw_value)
        scope = "core" if (req.action == "mem_write" and value.startswith("core/")) else ""
        contributing_tenants = set(pl.tenants)
        if req.resource is not None:
            contributing_tenants.update(req.resource.tenants)
        cross = any(tenant != cap.tenant for tenant in contributing_tenants)
        return {
            "action": {"name": req.action, "cls": spec["cls"]},
            "dest": {"host": host, "clearance": clr, "internal": bool(url_like and (not host or is_internal_host(host))),
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
        try:
            request_digest = req.digest
        except (AttributeError, TypeError, ValueError) as exc:
            self.audit.append({"action": str(getattr(req, "action", "<invalid>")),
                               "verdict": "deny", "checks": ["C13"],
                               "reason": f"invalid request encoding: {exc}"})
            return Decision("deny", [Violation("C13", "deny", "request contains non-canonical or invalid data")], "")
        if req.action not in ACTIONS:
            decision = Decision("deny", [Violation("C1", "deny", f"unknown action {req.action!r}")], request_digest)
            self.audit.append({"step": req.step, "task": req.cap.task_id, "action": req.action,
                               "verdict": "deny", "checks": decision.checks,
                               "digest": request_digest[:16], "principal": req.cap.principal})
            return decision
        spec, cap, v = ACTIONS[req.action], req.cap, []
        missing = []
        for name in spec.get("required", ()):
            arg = req.args.get(name)
            if arg is None or arg.value is None:
                missing.append(name)
            elif name == spec["target"] and (
                not isinstance(arg.value, str) or not arg.value.strip()
            ):
                missing.append(name)
        if missing:
            v.append(Violation("C13", "deny",
                               f"missing required argument(s): {', '.join(missing)}"))
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
            child = req.args.get("child_grants")
            child_grants = child.value if child is not None else None
            invalid = not isinstance(child_grants, dict)
            if not invalid:
                for act, patterns in child_grants.items():
                    parent_patterns = cap.grants.get(act)
                    if (not isinstance(act, str) or not isinstance(patterns, (list, tuple))
                            or parent_patterns is None
                            or not all(any(_grant_is_subset(pattern, parent) for parent in parent_patterns)
                                       for pattern in patterns)):
                        invalid = True
                        break
            if invalid:
                v.append(Violation("C11", "deny", "child grants are malformed or exceed parent authority"))

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
            approval_valid = False
            if req.approval is not None and self.approval_verifier is not None:
                try:
                    approval_valid = bool(self.approval_verifier(req, req.approval))
                except Exception:
                    approval_valid = False
            verdict = "allow" if approval_valid else "needs_approval"
        else:
            verdict = "allow"

        try:
            completed_obligations = self.obligations.run(obl, req=req)
        except Exception as exc:
            verdict = "deny"
            v.append(Violation("C0", "deny", f"obligation execution failed: {type(exc).__name__}"))
            completed_obligations = []
        d = Decision(verdict, v, request_digest, None, completed_obligations)
        if verdict == "allow":
            cap.calls += 1
            if is_egress:
                self.dests.setdefault(cap.task_id, set()).add(tval)
            nonce = os.urandom(32)
            token_payload = request_digest.encode("ascii") + b":" + nonce
            d.token = hmac.new(self.key, token_payload, hashlib.sha256).hexdigest()
            self._issued_tokens[d.token] = request_digest
        elif consequential:
            self.strikes[cap.task_id] = self.strikes.get(cap.task_id, 0) + 1
        self.audit.append({"step": req.step, "task": cap.task_id, "action": req.action, "verdict": verdict,
                           "checks": d.checks, "digest": request_digest[:16], "principal": cap.principal})
        return d

    def verify(self, req: Request, d: Decision) -> bool:
        """Verify and consume a single-use token for the exact authorised request."""
        if d.verdict != "allow" or d.token is None:
            return False
        if "C13" in self.disable:
            self.audit.append({"action": req.action, "verdict": "executor_verification_bypassed",
                               "digest": d.digest[:16]})
            return True
        try:
            current_digest = req.digest
        except (AttributeError, TypeError, ValueError):
            current_digest = None
        issued_digest = self._issued_tokens.pop(d.token, None)
        valid = current_digest is not None and d.digest == current_digest and issued_digest == current_digest
        self.audit.append({"action": req.action, "verdict": "executor_verified" if valid else "executor_rejected",
                           "digest": (current_digest or "")[:16]})
        return valid

    def scan(self, source: str, text: str, style: Optional[str]) -> bool:
        return False            # PACA++ does not rely on content classification

    def issue(self, cap: Capability) -> Capability:
        return cap


__all__ = ["Monitor", "AuditLog", "CHECKS", "host_of", "match_grant",
           "is_internal_host", "is_allowed_network_host", "canonical_path_target"]
