# Agent-lifecycle enforcement

**Status:** implemented reference checks for selected PACA-managed effect requests. This is stronger than an advisory prompt guard, but it is not a complete lifecycle monitor, host security boundary or provider security boundary.

## Why this exists

The security question is whether information and authority constraints remain valid as an agent moves from input and retrieval through memory, planning, tools, communication and consequential effects. A prompt-level refusal is not sufficient evidence: the protected resource must show that an unauthorized effect did not occur.

PACA contains useful, separately implemented controls for provenance, memory, authority, messaging, selected framework adapters and local resource commits. The `LifecycleSecurityController` connects a subset of these checks to effect requests made through `PACAAgentRuntime`. It does not automatically observe or mediate every transition in an agent's internal execution.

## What is enforced today

| Lifecycle segment | Current repository control | Actual boundary and evidence limit |
|---|---|---|
| Session start | `LifecycleSecurityController.start_session()` records principal, tenant, task, purpose and optional policy epoch. | The values are supplied by trusted host code. The controller does not authenticate the caller or independently establish workload identity. The host must derive them from an authenticated session source. |
| Input and retrieval | Trusted connector/ingress adapters can attach source identity, trust labels and lineage; `observe(...)` can record an input/retrieval audit event. | `observe()` is an audit hook, not an ingress enforcement point. It records metadata supplied by its caller; it does not capture every model input, retrieved result or hidden context dependency. Source identity depends on the trusted adapter. |
| Memory and context | `TrustedMemoryAdapter`, provenance/value stores, LangGraph BaseStore and PostgreSQL checkpoint wrappers enforce checks on supported mediated calls. | These are separate adapters, not universal hooks in the lifecycle controller. Direct raw SQLite/value-store access, raw checkpointer/SQL access and alternate memory paths can bypass them. Provenance metadata, values and operation-ledger state are not one cross-store atomic transaction. |
| Planning | `LifecycleSecurityPolicy.allowed_actions` and `allowed_tools` are evaluated when a typed candidate effect request reaches `authorize_request()`. | This constrains the proposed action/tool on the PACA runtime path. It does not inspect or constrain the model's private/internal planning process, nor every planner state transition. A plan is not itself a permit. |
| Tool execution | `PACAAgentRuntime.execute_effect()` / `aexecute_effect()` verify the request, authority, provenance, tool manifest and digest before entering the configured executor. Optional AgentDojo and LangChain middleware adapters mediate their registered paths. | Only calls routed through these configured paths are checked. Direct Python function calls, raw framework clients, alternate executors, subprocesses and provider clients remain potential bypasses. The AgentDojo workspace mapper supports a limited declared task/tool subset, not all AgentDojo tasks. |
| Communication and delegation | When a lifecycle controller is configured, `PACAAgentRuntime.delegate()`, `send_message()` and `receive_message()` bind the verified parent/sender/recipient authority context to the active session. The authority issuer still enforces delegation attenuation; the message codec still enforces recipient grants, envelope authentication, provenance, revocation and replay receipts. | This session gate covers only those runtime methods. Direct calls to `authority.issue()`, `messages.seal()` or `messages.open()`, alternate transports and raw framework paths do not pass through it. One controller represents one active principal/session; use separately authenticated controller/runtime instances for different agents. The callback is serialized against `stop()`/`close_session()`, but this is not distributed transactionality or network-delivery evidence. |
| Effect authorization | The lifecycle controller rechecks the frozen PACA `Request` for session binding, authority lineage, purpose, policy epoch, action/tool restrictions, selected argument lineage and tenant constraints. The runtime also verifies the signed capability and monitor decision. | This applies immediately before executor entry for requests routed through the PACA runtime. It does not protect direct calls outside that runtime. |
| Effect entry and resource commit | `commit_authorization()` consumes a bounded, process-local request-digest entry before the configured executor is entered. Separate local logical-resource and optional Linux filesystem adapters perform narrow fenced writes. In-process broker mediators and an optional Linux AF_UNIX transport support selected local logical-file reads/writes. | The lifecycle event means “authorization consumed before executor entry”; it is **not a receipt proving that the external effect committed**. The lifecycle digest set is lost on restart and is not shared across controller instances. Local resource fences do not implement remote SaaS/provider commit fencing. The AF_UNIX transport covers only operations explicitly routed through it. |
| Shutdown | `stop()` makes the controller reject subsequent effect requests that pass through it. | It cannot stop direct tools, raw stores, subprocesses or provider paths that bypass the PACA runtime and broker. |

The table is a code-path inventory, not evidence that every adapter has passed a matched adversarial evaluation. See [the Phase A baseline audit](LIFECYCLE_PHASE_A_BASELINE_AUDIT.md), [the direct-bypass evaluation](DIRECT_BYPASS_EVALUATION.md) and [the current implementation roadmap](security-roadmap.md).

## Runtime integration

Attach the controller to the reference runtime:

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

Every effect request routed through `execute_effect()` or `aexecute_effect()` is checked against the active lifecycle session. Consequential requests require immutable authority lineage, selected arguments must have complete lineage and acceptable integrity/tenant labels, and a typed tool manifest with an implementation digest is required for the configured action classes.

**Communication/delegation session binding:** with `lifecycle_security` configured, the runtime verifies the capability token and its immutable authority lineage, then executes `delegate()`, `send_message()` or `receive_message()` through `LifecycleSecurityController._run_context_transition()`. The controller checks principal, tenant, task, purpose and policy epoch against its active session while holding its lock. This prevents `stop()` or `close_session()` from racing the routed operation. Delegation still relies on the authority issuer for child-scope attenuation and quotas; message send/receive still relies on the message codec for target grants, envelope authentication, provenance, revocation, replay receipts and recipient memory authorization. Lifecycle audit events contain a digest and routing metadata, not the message payload. The method returns only after the local adapter operation completes; it does not prove network delivery or remote processing. Direct use of the authority issuer or message codec bypasses this runtime-level session gate.

**Identity boundary:** `session_id` is local controller context, not an authenticated request field. The host must derive principal, tenant, task and purpose from an authenticated workload/session source and must not allow an agent to choose them. A controller supports one active session at a time; concurrent sessions require separately managed controller/runtime instances.

**Executor boundary:** the manifest digest is capability-pinned, but the generic Python executor callback is trusted host configuration. The controller does not independently hash arbitrary Python callables or prove that a callback's code matches the manifest. The host must own the tool-to-executor mapping and prevent agent-controlled replacement.

**Replay boundary:** the controller's one-use digest set is bounded by `LifecycleSecurityPolicy.max_committed_effects` (default 100,000). It fails closed at capacity rather than evicting entries, but a restart loses this process-local set and separate controller instances do not share it. Do not treat it as durable or distributed replay protection. Retain the relevant authority-registry, monitor-ledger and resource-side replay controls.

## Broker and destination boundaries

The optional [Linux separate-process broker transport](UNIX_BROKER_DEPLOYMENT.md) uses AF_UNIX and kernel peer credentials (`SO_PEERCRED`) to bind configured worker UIDs/GIDs to fixed session context. Each connection receives a fresh session/channel binding and carries one operation. The configured dispatcher exposes only the read/write mediators supplied to it; those mediators narrow the actual operations further.

The tests include a separate child-process broker test and a constrained cross-UID fixture in which a worker reads a protected mode-0600 test file through the socket but cannot open that file directly. This is useful local IPC evidence. It is not proof that every worker resource path is mediated: the library does not create the OS identities or access-control policy, automatically start the broker, wire every runtime/framework operation through it, or remove workers' direct access to other resource clients. Production deployment must independently deny direct resource and credential access and exercise bypass tests under the actual service identities.

The optional Linux filesystem writer and logical-resource commit adapters protect only their declared local resource paths. Provider ingress adapters are read-only. No current PACA path supplies general destination-side commit-time authorization, conditional writes or ambiguous-delivery recovery for arbitrary SaaS providers.

## Position within the research landscape

- **CaMeL** is a direct baseline for trusted/untrusted data separation, value-level capabilities and tool-boundary information flow.
- **Progent** is a direct baseline for symbolic privilege restrictions and tool-argument policy updates.
- **Multi-CaMeL** is a direct baseline for preserving instruction/data separation and provenance across hierarchical agent communication.
- **AID-Guard** is a direct baseline for commit-time request/provider-state revalidation, reservations and ambiguous delivery/recovery under its declared provider contracts.
- **AgentDojo's native `tool_filter`** is a baseline for supported AgentDojo tasks and tools, not an enterprise-wide lifecycle monitor.

These are distinct controls, not interchangeable implementations. They must be tested in their native, pinned configurations where possible. Do not substitute a hand-coded imitation and label it as the original system. The machine-readable register currently marks external comparators as documentary/unrun; no matched result or superiority claim follows from the descriptions above.

## Research evidence versus engineering requirements

The research direction is to test whether a connected model of information provenance and authority continuity prevents violations that separate stage-specific controls miss. The experiment must observe the protected sink, not only model refusals or policy decisions. Measure prohibited effects/attack success, benign completion, false blocks, latency and cost; report indeterminate outcomes and uncertainty separately.

The reproducible protocol is documented in [the six-point comparative evaluation protocol](SIX_POINT_INDUSTRY_EVALUATION_PROTOCOL.md) and the four-dimension contract in [POLICY_CONTINUITY_EVALUATION.md](POLICY_CONTINUITY_EVALUATION.md). The lifecycle hypothesis remains unvalidated. No production-readiness, universal mediation, independent audit or superiority claim is made.

## Deployment rule

Use the lifecycle controller only for PACA-owned runtime calls and only with trusted host-provided session configuration. Treat every path that avoids the configured PACA runtime, adapters, broker or destination commit adapter as a bypass until it is separately integrated and tested. Do not claim complete mediation merely because the controller is enabled.
