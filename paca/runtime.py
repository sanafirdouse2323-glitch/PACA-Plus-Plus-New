"""Runtime objects shared by the monitor, baselines and scenarios."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any

from .authority import AuthorityLineage
from .provenance import Arg, Label

# action -> effect class, which argument names the target / payload / extra control values.
ACTIONS: dict[str, dict[str, Any]] = {
    "read_mail": {"cls": "read", "target": "folder", "required": ["folder"]},
    "mark_mail_read": {"cls": "write", "target": "folder", "required": ["folder"]},
    "read_calendar": {"cls": "read", "target": "resource", "required": ["resource"]},
    "read_drive": {"cls": "read", "target": "resource", "required": ["resource"]},
    "read_file": {"cls": "read", "target": "path", "required": ["path"]},
    "fetch_url": {
        "cls": "egress",
        "target": "url",
        "payload": ["query"],
        "required": ["url"],
    },  # URL label is also classified as outbound data
    "send_email": {
        "cls": "egress",
        "target": "to",
        "payload": ["body", "attachment"],
        "required": ["to", "body"],
    },
    "http_post": {
        "cls": "egress",
        "target": "url",
        "payload": ["body"],
        "required": ["url", "body"],
    },
    "post_message": {
        "cls": "egress",
        "target": "channel",
        "payload": ["text"],
        "required": ["channel", "text"],
    },
    "write_file": {
        "cls": "write",
        "target": "path",
        "payload": ["content"],
        "required": ["path", "content"],
    },
    "delete_file": {"cls": "destructive", "target": "path", "required": ["path"]},
    "run_command": {"cls": "exec", "target": "command", "required": ["command"]},
    "merge_pr": {"cls": "destructive", "target": "pr", "required": ["pr"]},
    "transfer_funds": {
        "cls": "destructive",
        "target": "account",
        "control": ["amount"],
        "required": ["account", "amount"],
    },
    "change_setting": {
        "cls": "setting",
        "target": "name",
        "payload": ["value"],
        "required": ["name", "value"],
    },
    "mem_read": {"cls": "read", "target": "key", "required": ["key"]},
    "mem_write": {
        "cls": "memory",
        "target": "key",
        "payload": ["value"],
        "required": ["key", "value"],
    },
    "delegate": {
        "cls": "delegate",
        "target": "agent",
        "payload": ["child_grants"],
        "required": ["agent", "child_grants"],
    },
    "call_tool": {"cls": "invoke", "target": "tool", "required": ["tool"]},
}


@dataclass(frozen=True)
class Tool:
    """A tool/MCP manifest as presented to the agent at call time."""

    name: str
    version: str
    description: str
    schema: tuple[str, ...] = ()
    implementation_digest: str | None = None

    def __post_init__(self) -> None:
        if self.implementation_digest is not None and (
            not isinstance(self.implementation_digest, str)
            or len(self.implementation_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.implementation_digest
            )
        ):
            raise ValueError(
                "implementation_digest must be a lowercase SHA-256 hexadecimal digest"
            )

    @property
    def hash(self) -> str:
        identity = [self.name, self.version, self.description, list(self.schema)]
        # Keep the historical hash byte-for-byte stable for legacy manifests.
        # New manifests opt in to binding the actual implementation artifact.
        if self.implementation_digest is not None:
            identity.append({"implementation_digest": self.implementation_digest})
        blob = json.dumps(identity, sort_keys=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class Capability:
    """Short-lived, task-bound, target-bound authority (not a standing role)."""

    cap_id: str
    principal: str
    tenant: str
    task_id: str
    role: str
    grants: dict[str, tuple[str, ...]]
    expires: int
    max_calls: int = 40
    max_fanout: int = 5
    tool_pins: dict[str, str] = field(default_factory=dict)
    parent: str | None = None
    calls: int = 0
    # Optional immutable authority history. Legacy callers remain supported, but
    # lineage-aware capabilities must keep this record aligned with their live fields.
    authority_lineage: AuthorityLineage | None = None

    def validate_authority_lineage(self) -> None:
        if self.authority_lineage is not None:
            self.authority_lineage.validate_capability(
                capability_id=self.cap_id,
                principal=self.principal,
                tenant=self.tenant,
                task_id=self.task_id,
                grants=self.grants,
                expires=self.expires,
                parent_id=self.parent,
                max_calls=self.max_calls,
            )


@dataclass
class Request:
    action: str
    args: dict[str, Arg]
    cap: Capability
    step: int
    tool: Tool | None = None
    resource: Label | None = None  # label of the object a read would return
    approval: str | None = None  # human approval, bound to this exact effect's digest
    evil: bool = False  # ground truth used only by the benchmark
    resource_lineage_refs: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if isinstance(self.resource_lineage_refs, (str, bytes)):
            raise TypeError(
                "resource_lineage_refs must be a collection of node identifiers"
            )
        refs = frozenset(self.resource_lineage_refs)
        if any(not isinstance(ref, str) or not ref for ref in refs):
            raise ValueError("resource lineage references must be non-empty strings")
        self.resource_lineage_refs = refs

    def values(self) -> dict[str, Any]:
        return {k: v.value for k, v in self.args.items()}

    @property
    def digest(self) -> str:
        """Stable digest of the action, arguments, provenance and authority snapshot."""

        def canonical(value: Any) -> Any:
            if value is None or isinstance(value, (str, bool, int)):
                return value
            if isinstance(value, float):
                if not math.isfinite(value):
                    raise ValueError(
                        "non-finite numbers are not valid request arguments"
                    )
                return value
            if isinstance(value, (list, tuple)):
                return [canonical(item) for item in value]
            if isinstance(value, dict):
                if any(not isinstance(key, str) for key in value):
                    raise TypeError("request object keys must be strings")
                return {key: canonical(value[key]) for key in sorted(value)}
            raise TypeError(
                f"unsupported request argument type: {type(value).__name__}"
            )

        def label_data(label: Label) -> dict[str, Any]:
            return {
                "integrity": label.integrity,
                "sensitivity": label.sensitivity,
                "tenants": sorted(label.tenants),
                "tenant_unknown": label.tenant_unknown,
                "origins": sorted(label.origins),
            }

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
            "id": self.cap.cap_id,
            "principal": self.cap.principal,
            "tenant": self.cap.tenant,
            "task": self.cap.task_id,
            "parent": self.cap.parent,
            "role": self.cap.role,
            "grants": {
                name: sorted(patterns)
                for name, patterns in sorted(self.cap.grants.items())
            },
            "expires": self.cap.expires,
            "max_calls": self.cap.max_calls,
            "max_fanout": self.cap.max_fanout,
            "tool_pins": dict(sorted(self.cap.tool_pins.items())),
            "authority_lineage": authority_data,
        }
        tool_data = None
        if self.tool is not None:
            tool_data = {
                "name": self.tool.name,
                "version": self.tool.version,
                "description": self.tool.description,
                "schema": list(self.tool.schema),
                "hash": self.tool.hash,
            }
            if self.tool.implementation_digest is not None:
                tool_data["implementation_digest"] = self.tool.implementation_digest

        payload = {
            "action": self.action,
            "args": args_data,
            "capability": cap_data,
            "step": self.step,
            "resource": label_data(self.resource)
            if self.resource is not None
            else None,
            "resource_lineage_refs": sorted(self.resource_lineage_refs),
            "tool": tool_data,
        }
        blob = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class Violation:
    check: str
    severity: str  # deny | escalate
    msg: str


@dataclass
class Decision:
    verdict: str  # allow | needs_approval | deny
    violations: list[Violation] = field(default_factory=list)
    digest: str = ""
    token: str | None = None
    obligations: list[str] = field(default_factory=list)

    @property
    def checks(self) -> list[str]:
        return sorted({v.check for v in self.violations})


@dataclass
class Effect:
    action: str
    values: dict[str, Any]
    evil: bool
    step: int
    note: str = ""


@dataclass
class World:
    effects: list[Effect] = field(default_factory=list)
    memory: dict[str, Arg] = field(default_factory=dict)
    # Labels are kept separately so a memory read can be authorized before value access.
    memory_labels: dict[str, Label] = field(default_factory=dict)

    def harmed(self) -> bool:
        return any(e.evil for e in self.effects)


__all__ = [
    "ACTIONS",
    "Capability",
    "Decision",
    "Effect",
    "Request",
    "Tool",
    "Violation",
    "World",
]
