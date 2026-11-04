"""Simplified models of control classes commonly deployed for LLM agents.

These are NOT the real products: each is a deliberately explicit, inspectable model of one
control *class* from the catalog's "Provider and platform record" (input filter, role-based
tool allow-list, sandbox + scoped permissions). Edit the constants to make them stricter.
"""
from __future__ import annotations

import fnmatch
from typing import Optional

from .monitor import host_of, is_internal_host, is_allowed_network_host
from .runtime import ACTIONS, Decision, Request, Violation

_BASE = {"read_mail", "read_file", "fetch_url", "http_post", "send_email", "post_message", "write_file", "run_command",
         "mem_write", "call_tool", "delegate", "change_setting"}
ROLE_TOOLS = {"assistant": _BASE, "devops": _BASE | {"delete_file", "merge_pr"}, "finance": _BASE | {"transfer_funds"}}

NET_ALLOW = ("corp.example", "partner.example", "storage.cloud.example", "github.com")
FS_SCOPE = ("/acme/", "/repo/", "/tmp/", "/tenants/", "/prod/")
EXEC_ALLOW = ("pytest*", "make *", "npm test", "git status", "ls*")
MCP_PREFIX = ("docs_", "crm_", "ext_")
SCAN_SOURCES = {"user", "email_external", "email_internal", "web", "rag", "repo", "ticket", "user_files"}


class Baseline:
    name, label, tracks_labels = "base", "", False

    def _out(self, req: Request, verdict: str, check: str = "", msg: str = "") -> Decision:
        if verdict == "needs_approval" and req.approval == req.digest:
            verdict = "allow"
        v = [Violation(check, "deny" if verdict == "deny" else "escalate", msg)] if check and verdict != "allow" else []
        return Decision(verdict, v, req.digest)

    def decide(self, req: Request) -> Decision:
        return self._out(req, "allow")

    def verify(self, req: Request, d: Decision) -> bool:
        return d.verdict == "allow"

    def scan(self, source: str, text: str, style: Optional[str]) -> bool:
        return False

    def issue(self, cap):
        return cap


class NoGuard(Baseline):
    name, label = "none", "No guard"


class PromptFilter(Baseline):
    """Input/prompt-attack classifier: catches 'classic' injections in user input and retrieved
    documents; does not see tool results, tool definitions, agent messages or memory ([22])."""
    name, label = "filter", "Prompt filter"

    def scan(self, source, text, style):
        return source in SCAN_SOURCES and style == "classic"


class StaticRBAC(Baseline):
    """Role-level tool allow-list (the original PACA++ evaluator is this: attributes -> permit/deny)."""
    name, label = "rbac", "Role-based allow-list"

    def decide(self, req):
        if req.action not in ROLE_TOOLS.get(req.cap.role, _BASE):
            return self._out(req, "deny", "RBAC", f"role {req.cap.role} may not use {req.action}")
        return self._out(req, "allow")


class SandboxScoped(Baseline):
    """Sandbox + scoped permissions + permission prompts (Claude-Code / Copilot-agent style, [16][20]):
    role tools, network allow-list, filesystem scope, command allow-list, prompts for destructive
    actions. Blind to data provenance, sensitivity and task boundaries."""
    name, label = "sandbox", "Sandbox + scoped permissions"

    def decide(self, req):
        a, v = req.action, req.values()
        if a not in ROLE_TOOLS.get(req.cap.role, _BASE):
            return self._out(req, "deny", "RBAC", f"role may not use {a}")
        spec = ACTIONS[a]
        tgt = str(v.get(spec["target"], ""))
        if a in ("fetch_url", "http_post"):
            h = host_of(tgt)
            if is_internal_host(h):
                return self._out(req, "deny", "SBX-net", "sandbox blocks internal/metadata endpoints")
            if (a == "http_post" or "query" in v) and not is_allowed_network_host(h, NET_ALLOW):
                return self._out(req, "needs_approval", "SBX-net", f"new network destination {h}")
        elif a == "send_email" and not is_allowed_network_host(host_of(tgt), NET_ALLOW):
            return self._out(req, "needs_approval", "SBX-net", f"new recipient domain {host_of(tgt)}")
        elif a in ("read_file", "write_file", "delete_file"):
            if not tgt.startswith(FS_SCOPE):
                return self._out(req, "deny", "SBX-fs", "path outside workspace")
            if a != "read_file" and "/.git/" in tgt:
                return self._out(req, "deny", "SBX-fs", ".git is read-only")
        elif a == "run_command" and not any(fnmatch.fnmatchcase(tgt, p) for p in EXEC_ALLOW):
            return self._out(req, "needs_approval", "SBX-exec", "command not on allow-list")
        elif a == "call_tool" and not tgt.startswith(MCP_PREFIX):
            return self._out(req, "deny", "SBX-mcp", "tool is not from an allowed MCP server")
        if spec["cls"] == "destructive":
            return self._out(req, "needs_approval", "ASK", "permission prompt for destructive action")
        return self._out(req, "allow")


__all__ = ["Baseline", "NoGuard", "PromptFilter", "StaticRBAC", "SandboxScoped", "ROLE_TOOLS"]
