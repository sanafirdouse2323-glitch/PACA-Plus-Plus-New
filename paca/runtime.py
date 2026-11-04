"""Runtime objects shared by the monitor, baselines and scenarios."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .provenance import Arg, Label

# action -> effect class, which argument names the target / payload / extra control values.
ACTIONS: Dict[str, Dict[str, Any]] = {
    "read_mail":      dict(cls="read",        target="folder"),
    "read_file":      dict(cls="read",        target="path"),
    "fetch_url":      dict(cls="egress",      target="url",     payload=["query"]),   # egress only if payload present
    "send_email":     dict(cls="egress",      target="to",      payload=["body", "attachment"]),
    "http_post":      dict(cls="egress",      target="url",     payload=["body"]),
    "post_message":   dict(cls="egress",      target="channel", payload=["text"]),
    "write_file":     dict(cls="write",       target="path",    payload=["content"]),
    "delete_file":    dict(cls="destructive", target="path"),
    "run_command":    dict(cls="exec",        target="command"),
    "merge_pr":       dict(cls="destructive", target="pr"),
    "transfer_funds": dict(cls="destructive", target="account", control=["amount"]),
    "change_setting": dict(cls="setting",     target="name",    payload=["value"]),
    "mem_read":       dict(cls="read",        target="key"),
    "mem_write":      dict(cls="memory",      target="key",     payload=["value"]),
    "delegate":       dict(cls="delegate",    target="agent",   payload=["child_grants"]),
    "call_tool":      dict(cls="invoke",      target="tool"),
}


@dataclass(frozen=True)
class Tool:
    """A tool/MCP manifest as presented to the agent at call time."""
    name: str
    version: str
    description: str
    schema: Tuple[str, ...] = ()

    @property
    def hash(self) -> str:
        blob = json.dumps([self.name, self.version, self.description, list(self.schema)], sort_keys=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class Capability:
    """Short-lived, task-bound, target-bound authority (not a standing role)."""
    cap_id: str
    principal: str
    tenant: str
    task_id: str
    role: str
    grants: Dict[str, Tuple[str, ...]]
    expires: int
    max_calls: int = 40
    max_fanout: int = 5
    tool_pins: Dict[str, str] = field(default_factory=dict)
    parent: Optional[str] = None
    calls: int = 0


@dataclass
class Request:
    action: str
    args: Dict[str, Arg]
    cap: Capability
    step: int
    tool: Optional[Tool] = None
    resource: Optional[Label] = None        # label of the object a read would return
    approval: Optional[str] = None          # human approval, bound to this exact effect's digest
    evil: bool = False                      # ground truth used only by the benchmark

    def values(self) -> Dict[str, Any]:
        return {k: v.value for k, v in self.args.items()}

    @property
    def digest(self) -> str:
        """Stable digest of the action, arguments, provenance and authority snapshot."""
        def canonical(value: Any) -> Any:
            if value is None or isinstance(value, (str, bool, int)):
                return value
            if isinstance(value, float):
                if not math.isfinite(value):
                    raise ValueError("non-finite numbers are not valid request arguments")
                return value
            if isinstance(value, (list, tuple)):
                return [canonical(item) for item in value]
            if isinstance(value, dict):
                if any(not isinstance(key, str) for key in value):
                    raise TypeError("request object keys must be strings")
                return {key: canonical(value[key]) for key in sorted(value)}
            raise TypeError(f"unsupported request argument type: {type(value).__name__}")

        def label_data(label: Label) -> Dict[str, Any]:
            return {"integrity": label.integrity, "sensitivity": label.sensitivity,
                    "tenants": sorted(label.tenants), "origins": sorted(label.origins)}

        args_data = {}
        for name in sorted(self.args):
            arg = self.args[name]
            if not isinstance(arg, Arg):
                raise TypeError(f"request argument {name!r} must be an Arg")
            args_data[name] = {"value": canonical(arg.value), "label": label_data(arg.label)}

        cap_data = {
            "id": self.cap.cap_id, "principal": self.cap.principal, "tenant": self.cap.tenant,
            "task": self.cap.task_id, "parent": self.cap.parent, "role": self.cap.role,
            "grants": {name: sorted(patterns) for name, patterns in sorted(self.cap.grants.items())},
            "expires": self.cap.expires, "max_calls": self.cap.max_calls,
            "max_fanout": self.cap.max_fanout, "tool_pins": dict(sorted(self.cap.tool_pins.items())),
        }
        payload = {
            "action": self.action, "args": args_data, "capability": cap_data, "step": self.step,
            "resource": label_data(self.resource) if self.resource is not None else None,
            "tool": None if self.tool is None else {
                "name": self.tool.name, "version": self.tool.version, "description": self.tool.description,
                "schema": list(self.tool.schema), "hash": self.tool.hash,
            },
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class Violation:
    check: str
    severity: str            # deny | escalate
    msg: str


@dataclass
class Decision:
    verdict: str             # allow | needs_approval | deny
    violations: List[Violation] = field(default_factory=list)
    digest: str = ""
    token: Optional[str] = None
    obligations: List[str] = field(default_factory=list)

    @property
    def checks(self) -> List[str]:
        return sorted({v.check for v in self.violations})


@dataclass
class Effect:
    action: str
    values: Dict[str, Any]
    evil: bool
    step: int
    note: str = ""


@dataclass
class World:
    effects: List[Effect] = field(default_factory=list)
    memory: Dict[str, Arg] = field(default_factory=dict)

    def harmed(self) -> bool:
        return any(e.evil for e in self.effects)


__all__ = ["ACTIONS", "Tool", "Capability", "Request", "Violation", "Decision", "Effect", "World"]
