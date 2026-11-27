# Agent-lifecycle enforcement

**Status:** implemented reference control for PACA-managed runtime calls. This is
stronger than an advisory prompt guard, but it is not a host or provider security
boundary.

## Why this exists

Research on indirect prompt injection, excessive agency, memory poisoning and
tool abuse consistently finds that the harmful step is the transition from
untrusted information to an authorized side effect. Prompt-only defenses are
weak and benchmark scores are often optimistic when they measure semantic
compliance instead of observed harm. PACA already had useful capability,
provenance and commit primitives; this milestone makes their lifecycle use
explicit and fail closed at the reference runtime's final effect boundary.

## Lifecycle contract

| Phase | Required control | PACA implementation |
|---|---|---|
| Session start | Bind principal, tenant, task and purpose | `LifecycleSecurityController.start_session()` |
| Input/retrieval | Record source and trust; never treat tool output as instructions | `observe(..., trusted=False)` plus trusted adapters that create labelled `Arg` values |
| Planning | Constrain the action/tool set before invocation | `LifecycleSecurityPolicy.allowed_actions` and `allowed_tools` |
| Tool invocation | Require a typed, capability-pinned tool manifest with an implementation digest | `require_tool_for` and `require_tool_implementation_digest`; the host-supplied executor mapping remains trusted configuration |
| Memory/context | Preserve complete lineage and tenant binding | `require_complete_lineage_for`, `Arg.lineage_refs`, and `Label` checks |
| Inter-agent transfer | Keep the session binding and signed message path | existing PACA message codec plus runtime session checks |
| Effect authorization | Re-check the frozen request immediately before the monitor | `authorize_request()` |
| Effect commit | Consume a one-use request digest and audit the commit | `commit_authorization()` plus the existing monitor token and authority registry |
| Shutdown/response | Stop all subsequent effects on operator action | `stop()`; create a new controller to resume after incident handling |

The session can also bind an authority `policy_epoch`. When supplied, the
request's immutable authority lineage must carry the same epoch. This makes a
policy change or revocation epoch a visible continuity boundary rather than an
implicit assumption.

The `session_id` is a controller-local audit/context identifier. It is not carried in `Request` or independently authenticated by the transport. The host must derive principal, tenant, task and purpose from an authenticated workload/session source, and must not allow an agent to choose those values. A controller supports one active session at a time; use separately managed controller/runtime instances for concurrent sessions. The session ID alone is not proof of identity.

The controller records metadata only: action names, identities, digests,
decisions and reasons. It never stores model text, credentials or effect
payloads in its audit events.

## Runtime integration

Attach it to `PACAAgentRuntime`:

```python
from paca.lifecycle import LifecycleSecurityController

lifecycle = LifecycleSecurityController()
lifecycle.start_session(
    session_id="session-42",
    principal="agent-7",
    tenant="acme",
    task_id="task-9",
    purpose="prepare_customer_report",
    policy_epoch=authority.registry.current_epoch,
)

runtime = PACAAgentRuntime(
    authority=authority,
    memory=memory,
    monitor=monitor,
    messages=messages,
    lifecycle_security=lifecycle,
)
```

Every call through `execute_effect()` or `aexecute_effect()` is then bound to
the active task and tenant. Consequential actions require complete lineage,
reject untrusted arguments, require a digest-pinned tool manifest, and cannot
reuse the same request digest. `lifecycle.stop("incident-123")` is a one-way
kill switch for that controller instance.

**Important implementation boundaries:** the manifest digest is included in the capability-pinned tool identity, but the generic Python executor callback is still supplied by trusted host code. The lifecycle controller does not independently hash arbitrary Python callables or prove that a callback's code matches the manifest digest. The deployment must maintain an explicit trusted tool-to-executor mapping and must not let the agent select or replace executor callbacks.

The one-use digest set is process-local. It is bounded by `LifecycleSecurityPolicy.max_committed_effects` (default 100,000); reaching the limit denies further commits rather than evicting receipts. A process restart loses this controller-local set, and separate controller instances do not share it. Do not treat it as durable or distributed replay protection; retain the authority-registry, monitor-ledger and destination-side replay checks that apply to the deployment.

## Research evidence versus engineering requirements

The research record supports the direction, not a universal security claim:

1. InjecAgent and Agent Security Bench demonstrate that tool-using agents remain
   vulnerable to indirect injection and memory/tool attacks, often at high rates.
2. Progent, AgentSys, AgentVisor and AgentArmor report substantial reductions
   when enforcement is deterministic, privilege-scoped and context-isolated.
3. SafeClawBench-style evaluations show that semantic checks can pass while the
   sandbox still records harm; observed effects and stateful traces must be
   measured separately.
4. Provenance, cryptographic source binding and tamper-resistant memory remain
   valuable engineering patterns, but are not by themselves broadly validated
   production controls.

Therefore this module is a necessary lifecycle control, not sufficient evidence
for production readiness. A production deployment must additionally remove the
agent's direct access to raw stores, credentials, subprocesses and provider
clients; enforce network and OS isolation; broker short-lived secrets; mediate
destination-side commits; and test adaptive, multi-session attacks.

The reproducible four-dimension evaluation protocol is documented in
[`docs/POLICY_CONTINUITY_EVALUATION.md`](POLICY_CONTINUITY_EVALUATION.md). It
requires separate evidence for authority, information, usage and effect
continuity across transformations, delegation, retries, revocation races and
external sink outcomes.

## Deployment rule

Use this controller for PACA-owned runtime calls. Treat any path that can avoid
`PACAAgentRuntime`, the broker, the memory adapter or a destination commit
adapter as a bypass until it is separately integrated and tested. Do not claim
complete mediation solely because this controller is enabled.

