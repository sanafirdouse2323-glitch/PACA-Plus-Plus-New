"""Runtime objects shared by the monitor, baselines and scenarios."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .authority import AuthorityLineage
from .provenance import Arg, Label

# action -> effect class, which argument names the target / payload / extra control values.
ACTIONS: Dict[str, Dict[str, Any]] = {
    "read_mail":      dict(cls="read",        target="folder",   required=["folder"]),
    "mark_mail_read": dict(cls="write",       target="folder",   required=["folder"]),
    "read_calendar":  dict(cls="read",        target="resource", required=["resource"]),
    "read_drive":     dict(cls="read",        target="resource", required=["resource"]),
    "read_file":      dict(cls="read",        target="path",     required=["path"]),
    "fetch_url":      dict(cls="egress",      target="url",     payload=["query"], required=["url"]),   # URL label is also classified as outbound data
    "send_email":     dict(cls="egress",      target="to",      payload=["body", "attachment"], required=["to", "body"]),
    "http_post":      dict(cls="egress",      target="url",     payload=["body"], required=["url", "body"]),
    "post_message":   dict(cls="egress",      target="channel", payload=["text"], required=["channel", "text"]),
    "write_file":     dict(cls="write",       target="path",    payload=["content"], required=["path", "content"]),
    "delete_file":    dict(cls="destructive", target="path",    required=["path"]),
    "run_command":    dict(cls="exec",        target="command", required=["command"]),
    "merge_pr":       dict(cls="destructive", target="pr",      required=["pr"]),
    "transfer_funds": dict(cls="destructive", target="account", control=["amount"], required=["account", "amount"]),
    "change_setting": dict(cls="setting",     target="name",    payload=["value"], required=["name", "value"]),
    "mem_read":       dict(cls="read",        target="key",     required=["key"]),
    "mem_write":      dict(cls="memory",      target="key",     payload=["value"], required=["key", "value"]),
    "delegate":       dict(cls="delegate",    target="agent",   payload=["child_grants"], required=["agent", "child_grants"]),
    "call_tool":      dict(cls="invoke",      target="tool",    required=["tool"]),
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
    # Optional immutable authority history. Legacy callers remain supported, but
    # lineage-aware capabilities must keep this record aligned with their live fields.
    authority_lineage: Optional[AuthorityLineage] = None

    def validate_authority_lineage(self) -> None:
        if self.authority_lineage is not None:
            self.authority_lineage.validate_capability(
                principal=self.principal,
                tenant=self.tenant,
                task_id=self.task_id,
                grants=self.grants,
                expires=self.expires,
                has_parent=self.parent is not None,
            )


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
    resource_lineage_refs: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if isinstance(self.resource_lineage_refs, (str, bytes)):
            raise TypeError("resource_lineage_refs must be a collection of node identifiers")
        refs = frozenset(self.resource_lineage_refs)
        if any(not isinstance(ref, str) or not ref for ref in refs):
            raise ValueError("resource lineage references must be non-empty strings")
        self.resource_lineage_refs = refs

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
                    "tenants": sorted(label.tenants), "tenant_unknown": label.tenant_unknown,
                    "origins": sorted(label.origins)}

        args_data = {}
        for name in sorted(self.args):
            arg = self.args[name]
            if not isinstance(arg, Arg):
                raise TypeError(f"request argument {name!r} must be an Arg")
            args_data[name] = {
                "value": canonical(arg.value),
                "label": label_data(arg.label),
                "lineage_refs": sorted(arg.lineage_refs),
                "lineage_incomplete": arg.lineage_incomplete,
            }

        self.cap.validate_authority_lineage()
        authority_data = (
            self.cap.authority_lineage.as_dict()
            if self.cap.authority_lineage is not None
            else None
        )
        cap_data = {
            "id": self.cap.cap_id, "principal": self.cap.principal, "tenant": self.cap.tenant,
            "task": self.cap.task_id, "parent": self.cap.parent, "role": self.cap.role,
            "grants": {name: sorted(patterns) for name, patterns in sorted(self.cap.grants.items())},
            "expires": self.cap.expires, "max_calls": self.cap.max_calls,
            "max_fanout": self.cap.max_fanout, "tool_pins": dict(sorted(self.cap.tool_pins.items())),
            "authority_lineage": authority_data,
        }
        payload = {
            "action": self.action, "args": args_data, "capability": cap_data, "step": self.step,
            "resource": label_data(self.resource) if self.resource is not None else None,
            "resource_lineage_refs": sorted(self.resource_lineage_refs),
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
    # Labels are kept separately so a memory read can be authorized before value access.
    memory_labels: Dict[str, Label] = field(default_factory=dict)

    def harmed(self) -> bool:
        return any(e.evil for e in self.effects)


__all__ = ["ACTIONS", "Tool", "Capability", "Request", "Violation", "Decision", "Effect", "World"]
