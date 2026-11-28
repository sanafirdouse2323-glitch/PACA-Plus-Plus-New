# Lifecycle evaluation — Phase A baseline audit and threat model

**Repository:** `PACA-Plus-Plus-New` only.  
**Assessment date:** 28 November 2026.  
**Code baseline:** PR #49 merge `c9d06c4796a9fb0a04cd5db1ca4c792d2396506a`.  
**Current documentation/repository head inspected:** `5b8103b5949b9bfce2488b96a4890d59dba7e527` on `main`.  
**Status:** initial Phase A source-and-documentation audit; Phase A has not yet met its exit criteria. A bounded AgentDojo workspace pilot profile is now specified, but it has not been live-executed or approved as a confirmatory study. No new comparative experiment or live model run is claimed.

The comparison between the code baseline and the inspected `main` head shows that the intervening commits changed workflows, the Dockerfile and documentation, but no `paca/` implementation modules. The implementation baseline therefore remains PR #49 for this audit. The repository's current CI run on the inspected `main` head succeeded, including the broker UID-isolation and AgentDojo adapter jobs; its credential-dependent live AgentDojo model benchmark was skipped. CI success is not a live-agent effectiveness result.

## 1. Purpose and decision rule

Phase A freezes the system boundary, threat model, protected effects, adapter inventory, comparator eligibility and evidence rules before any confirmatory lifecycle experiment. It is not a code-expansion phase.

The research hypothesis to be tested is:

> A connected policy model that preserves information provenance and authority constraints across input/retrieval, memory/context, planning, tool execution, communication/delegation and consequential effect commitment will prevent lifecycle-spanning policy violations that are missed by isolated stage controls, while retaining useful benign-task completion.

This hypothesis remains unvalidated. A larger lifecycle diagram, a passing unit test, a policy-deny result or a model refusal does not establish the hypothesis. A security result requires an observable protected sink and evidence that the prohibited effect did not occur under the declared threat model.

**Phase A decision rule:** do not add a generic lifecycle component merely to fill a diagram gap. First freeze the scenario and policy, establish which existing baseline covers it, reproduce any residual violation against the strongest applicable baseline, and only then decide whether a PACA extension is justified.

## 2. Six-stage implementation and evidence inventory

The table distinguishes (a) code that exists, (b) the path it actually mediates and (c) the property not yet established. “Partial” means selected adapter paths only, not that the complete lifecycle stage is protected.

| Lifecycle stage | Existing implementation on the code baseline | Current enforcement/evidence boundary | Phase A gap to test |
|---|---|---|---|
| **1. Input and retrieval** | Trusted connector ingress and provider-capture abstractions; read-only Gmail, Microsoft Graph, Slack and Qdrant adapters; provenance labels and lineage records; lifecycle `observe()` hook. | Provider adapters are host-side reference connectors; CI uses mocked HTTP, not live accounts. `observe()` records caller-supplied phase/metadata and an optional trust marker. It is not an interception point and does not capture every user prompt, tool result, retrieved document or hidden context dependency. | Establish the real source identity, tenant, trust and version available at ingress. Test missing/forged source metadata, indirect prompt injection and tool-returned instructions. Inventory every input/retrieval route used by the chosen agent. |
| **2. Memory and context** | `TrustedMemoryAdapter`, separate SQLite value and provenance stores, authority/tenant/purpose checks, digest validation, lineage derivation/revocation, LangGraph BaseStore wrapper and PostgreSQL checkpoint wrapper. | Selected mediated operations are checked. Direct raw SQLite/value-store access, raw PostgresSaver/SQL credentials and alternate stores can bypass wrappers. Value, provenance and Monitor operation-ledger state do not share one cross-store atomic transaction. | Test write, read, retrieval, cross-session reuse, compaction/summarisation, poisoning, deletion and revocation. Prove both the mediated decision and the bytes/metadata actually returned. Try direct raw-store access as a negative-control bypass. |
| **3. Planning** | The lifecycle phase enum can label a plan event; `LifecycleSecurityPolicy.allowed_actions` and `allowed_tools` constrain candidate requests when `authorize_request()` is called. | The lifecycle `observe()` call is audit-only. The controller does not inspect the model's internal reasoning/planning state or automatically intercept every planner transition. The action/tool allowlist is applied to a typed effect request on the PACA runtime path, not to every possible internal proposal. | Treat plan output strictly as a proposal. Record the plan/action candidate, the context that influenced it and the later executable request. Test whether untrusted content changes the proposed target/action and whether the final request is independently re-authorized. Do not claim hidden chain-of-thought inspection. |
| **4. Tool execution** | `PACAAgentRuntime.execute_effect()` / `aexecute_effect()`; typed request snapshots; capability, policy, provenance, tool-manifest and effect-token checks; optional AgentDojo ToolsExecutor, LangChain middleware and LangGraph integrations; optional Docker worker. | Checks apply only to calls that use the configured PACA runtime/adapter. Direct Python tool invocation, raw framework objects, alternate executors, subprocesses and provider clients remain possible bypasses. Docker enforcement is opt-in and applies only to supported `run_command` calls routed through that runtime. AgentDojo mapping covers a limited declared workspace/task subset. | Inventory every executable tool path and test both mediated and bypass attempts. Pin the exact tool implementation and task set. Measure whether denial happens before the tool is entered, not merely after a tool result is returned. |
| **5. Communication and delegation** | Capability delegation and attenuation checks; signed message codec; message receipts and quotas; provenance-bearing message payloads; local broker session context. | These controls are separate from the lifecycle controller. In the inspected code, `PACAAgentRuntime.delegate()`, `send_message()` and `receive_message()` call authority/message components but do not bind each operation to the active lifecycle controller session or emit controller-enforced phase transitions. Multi-hop provenance/authority continuity is not established merely by the existence of signed messages or an authority graph. | Test sender and recipient identity, message type, task/purpose, provenance labels, multi-hop forwarding, delegation attenuation, replay, policy changes mid-task, revoked parents and untrusted-data-as-instruction relabelling. Compare Multi-CaMeL using its native channel protocol where reproducible. |
| **6. Effect authorization and commitment** | Monitor decisions and request digests; one-use lifecycle request-digest check before executor entry; logical `FencedResourceExecutor`; optional Linux `FilesystemFencedResourceExecutor`; in-process logical-file read/write mediators; optional AF_UNIX transport for configured local mediators; SQLite/PostgreSQL reference commit and replay paths. | `LifecycleSecurityController.commit_authorization()` records that authorization was consumed before executor entry; it is not evidence that the external effect actually committed. Its digest set is process-local and lost on restart. Local resource fences cover selected local operations only. The optional AF_UNIX broker is a narrow separate-process IPC path; it is not automatically wired into all runtimes or all resource routes. Provider connectors are read-only; no general remote-provider commit fence or ambiguous-delivery protocol exists. | Observe an effect sink with before/after state and unique commit receipts. Exercise changed arguments/target, policy-epoch change, revocation races, concurrent commit, duplicate delivery, timeout after possible commit, retry, crash/restart and reconciliation. Reproduce AID-Guard's declared commit/reservation/recovery semantics on eligible provider contracts before claiming a residual gap. |

### Existing regression evidence to reuse

The code baseline already has meaningful, targeted tests. Phase A should reuse and extend them rather than recreate simplified versions:

| Existing evidence | What the tests demonstrate | What they do not demonstrate |
|---|---|---|
| `tests/test_lifecycle_security.py` | Untrusted content may be read but is rejected for selected egress; consequential requests require lineage/tool binding; session, kill-switch, purpose/epoch and bounded one-use behavior are checked. | All lifecycle phases being automatically observed or enforced, durable cross-process lifecycle receipts, or external-sink commit confirmation. |
| `tests/test_semantic_transformations.py` | Explicit lineage and restrictions survive rewording, compaction, retrieval, agent transfer and fragment combination; opaque model output with missing source edges stays incomplete. | Discovery of hidden dependencies that the trusted adapter did not supply, or model-in-the-loop semantic reconstruction effectiveness. |
| `tests/test_durable_lifecycle.py` | Durable lineage/revocation, inter-agent envelope sender/recipient authentication, message replay after registry restart, concurrent duplicate delivery, framework adapters and raw value-store bypass are covered by named regression cases. | A matched six-stage live-agent trajectory or complete process/host mediation. |
| `tests/test_lifecycle_bypass_matrix.py` | Direct subprocess filesystem writes and direct Python tool invocation can bypass Python mediation and LangChain middleware. | An exhaustive inventory of every bypass on a deployed host. These are negative controls showing why mediation claims must be scoped. |
| `tests/test_unix_broker.py` | Peer UID/GID binding, one-shot sessions, distinct broker process, wrong broker UID rejection and a root-to-`nobody` protected-file access fixture are exercised. | A general sandbox, every protected resource, remote network mediation or production service deployment. |
| `tests/test_agentdojo_benchmark.py` | The benchmark runner passes AgentDojo's official `tool_filter` defense configuration and distinguishes some indeterminate/operational outcomes. | A live model comparison in the current CI run; the credential-gated preflight, benchmark and result-upload steps were skipped. |

These tests are valuable regression evidence for their declared fixtures. The negative-control tests are especially important: they demonstrate bypasses rather than claiming to have closed them.

### Cross-cutting boundaries

- **Identity and task ownership:** session values, source metadata, tenant mapping, task context and tool mappings are supplied by trusted host integrations. The controller does not itself authenticate an OIDC/workload identity. The AF_UNIX broker maps kernel-authenticated local UIDs/GIDs to preconfigured identity fields; that mapping is not an identity provider.
- **Information semantics:** digests establish integrity relative to supplied bytes/metadata, not truth or semantic safety. Declared lineage does not automatically reveal every hidden model-context dependency or semantic reconstruction.
- **State consistency:** SQLite provenance/value/operation state and the PostgreSQL single-primary authority registry are separate state domains. Do not call them a single distributed lifecycle store.
- **Broker/host isolation:** `paca/unix_broker.py` implements an optional Linux AF_UNIX transport with `SO_PEERCRED`, one operation per connection and configured read/write mediators. A constrained cross-UID fixture demonstrates one protected-file read through the socket while direct access to that test file is denied. The library does not configure service identities, OS access controls, credential isolation or mandatory routing through the broker. Other direct resource paths remain outside it.
- **Effect semantics:** an authorization decision, a consumed one-use permit, executor entry and a destination-confirmed commit are four different events. The trace must never treat one as proof of the next.
- **Audit and observability:** local audit metadata and simulator output are not tamper-resistant production evidence. Retain sink-side receipts and reviewed traces, and redact credentials, prompts and provider records.

## 3. Threat model to freeze before experiments

### 3.1 Protected assets and security properties

The initial Phase A scope should identify these assets explicitly:

1. Protected records, files, messages, memory values, provider objects and external business effects.
2. Credentials, signing keys, capability tokens, workload identity and tenant/task context.
3. Information labels, provenance graphs, authority/delegation graphs, revocation state, policy epochs, usage counters and commit receipts.
4. Agent plans, tool requests, inter-agent messages, memory writes and recovery/retry state.
5. Audit/evaluation traces needed to prove what was authorized and what actually happened.

For each protected action, the policy fixture must specify principal, tenant, task, purpose, source/data class, action, target/recipient, required approval, policy version/epoch, permitted usage and expected sink state.

### 3.2 Adversary capabilities in scope

Assume an attacker can supply or control untrusted user content, retrieved documents, tool results or messages; exploit indirect prompt injection; influence a model-generated plan; poison persistent memory; cause a downstream agent to reinterpret forwarded data; request delegation beyond intended scope; replay a valid old message/request; race revocation against an operation; cause timeouts or uncertain delivery; and attempt direct use of any raw client, database handle, framework API, subprocess or alternate tool path available to the worker.

Test malicious or compromised sub-agents as untrusted principals unless the frozen experiment explicitly treats them as trusted. Test stale/incorrect source metadata and tool-manifest substitution where the application boundary permits those attacks.

### 3.3 Trusted computing base and assumptions

The experiment must list, version and protect at least:

- orchestrator/session authority and the code that binds principal, tenant, task and purpose;
- trusted input/provider adapters and source-identity/version capture;
- capability issuer, signing key, verifier key ring and key-distribution configuration;
- policy engine, effect monitor and tool-name-to-executor mapping;
- lifecycle runtime and any framework adapter relied on for enforcement;
- broker process, peer-UID/GID configuration, socket directory/permissions and host kernel;
- SQLite/PostgreSQL instances, schemas, database roles and failover configuration;
- provenance/memory release callbacks and resource-side commit adapters;
- effect sink/provider contract, idempotency keys, conditional-write semantics and receipt authority; and
- test harness, policy oracle, clocks, reset procedure and trace collector.

The host kernel, broker configuration, trusted issuer/verifier keys and test oracle are trusted in the initial local experiment. A compromised kernel, repository administrator or trusted issuer is outside that first experiment unless a separate fault/threat profile is specified. These exclusions must be stated, not silently treated as solved.

### 3.4 Explicit non-goals for the first experiment

Do not claim resistance to arbitrary kernel compromise, all possible model prompt-injection strategies, every vendor/provider or every agent framework, semantic truth verification, covert side channels, or all forms of denial of service. Do not pool incompatible provider commit contracts or incomparable task semantics. Do not claim production readiness or general-purpose host sandboxing.

## 4. Baseline and comparator plan

The external comparator must be the actual pinned system or its published native protocol—not a hand-written imitation. Record version/commit, native configuration, threat model, policy, supported actions, mediation point, exclusions, adapter and raw outputs. A documentary description is not a runtime result.

| Comparator | Stage/property where it is a relevant baseline | Phase A handling | Current evidence in the repository register |
|---|---|---|---|
| **AgentDojo native `tool_filter`** | Tool filtering and task utility on the supported AgentDojo workspace subset. | Use the benchmark's native filter unchanged. Confirm identical eligible tasks, tool schemas, model, prompts and iteration limit. The current runner has fixed condition order and no run-level seed control, so its first execution is a pilot, not a confirmatory estimate. | The adapter and the official `tool_filter` configuration are tested. The credential-dependent live model run on 28 November was skipped. See [the bounded pilot profile](PHASE_A_AGENTDOJO_PILOT_PROFILE.md); it is specified but not live-reproduced. |
| **CaMeL** | Trusted/untrusted data separation, value-level capabilities and information-flow checks at tool boundaries. | Pin the paper/implementation and native task setup. Use only scenarios compatible with its threat model and interpreter; do not alter semantics to force a match. | D / not run. |
| **Progent** | Symbolic tool/argument constraints and privilege narrowing/expansion. | Pin implementation and supported policy language; establish native execution path before comparison. | D / not run. |
| **Multi-CaMeL** | Cross-agent instruction/data separation and provenance transfer in hierarchical agent-as-tool communication. | Reproduce its native message-channel protocol and supported MultiAgentDojo/AssetOpsBench setup where dependencies and tasks are available. Do not replace it with PACA's signed message codec. | Public artifact `james-pete/multiagentdojo` source-pinned to `e71647382155dc6949d6ccf9a9d7ec7cf429b856` (its inspected `main` head on 28 November 2026); source only, not installed or executed. Evidence remains D / not run. |
| **AID-Guard** | Commit-time request/provider-state validation, reservations, ambiguous delivery, retry and recovery under declared provider contracts. | Reproduce its pinned prototype and declared test sinks/provider contracts. Compare exact effect ordering and recovery semantics; do not treat local PACA write fencing as equivalent remote-provider support. | D / not run. |
| **Other relevant prior art** | Memory poisoning, delegation, durable replay and runtime containment. | Use the six-point protocol's register to select task-appropriate controls (e.g., MPBench, AgentPoison, DelegateGuard, Delegation Without Trust, CapLease, OpenShell). Keep distinct dimensions in separate strata. | External entries in the comparator register are D / not run. |
| **PACA ablations** | Identify contribution of information provenance, authority, revocation, lifecycle checks and effect fencing. | Run only after the full treatment and policy are frozen; ensure each ablation removes one declared mechanism without changing unrelated semantics. | Not a comparative result yet. |

The machine-readable comparator register contains 16 external entries plus PACA. The 16 external entries are currently documentary evidence (`D`) with `live_test_status: not_run`. The hand-authored simulator baselines are evidence type `S` and remain useful for regression only. Do not elevate them to vendor/research comparator results.

## 5. Scenario design and observable sink

Use one versioned scenario schema that can represent a connected six-stage trajectory. Every scenario should carry:

- immutable template ID, variant ID, run ID, seed and task/prompt version;
- principal, workload, tenant, task, purpose and policy version/epoch;
- source IDs, source trust, content digest, parent lineage and transformation events;
- memory object/version writes and reads, including session boundaries;
- proposed plan/action, tool identity/manifest digest and exact normalized arguments;
- delegation parent/child capability IDs, constraints, recipient and message envelope metadata;
- authorization, revocation, quota, reservation, replay and policy decisions with reason codes;
- sink state before/after, destination-side commit receipt, idempotency key and commit timestamp/sequence;
- retries, timeouts, restarts, recovery actions, indeterminate outcomes and raw trace hashes.

The security oracle is the protected sink plus its trusted receipt/state history. A denied policy decision is not sufficient if the sink changed. A benign task is not successful merely because no prohibited action occurred; the expected legitimate workflow must also complete.

### Minimum adversarial families for the first connected corpus

1. Indirect injection arriving through user input, retrieval and tool-returned content.
2. Memory poisoning, delayed activation, compaction/summarisation and cross-session reuse.
3. Plan manipulation where the untrusted source is not repeated in the final tool arguments.
4. Unauthorized action, tool substitution, changed target/arguments and alternate/direct execution paths.
5. Message forwarding, multi-hop agent delegation, provenance relabelling, replay and cross-tenant/purpose mismatch.
6. Policy-epoch change, authority revocation, quota/replay exhaustion and races immediately before/after effect authorization.
7. Commit timeout with unknown outcome, exact retry, duplicate delivery, process restart and recovery/reconciliation.
8. Benign control tasks and benign transformations to estimate utility and false denials.

Use the existing 30 attack and 11 benign scenarios as development/regression fixtures only. Confirmatory scenarios must be newly versioned and disjoint by underlying workflow template; multiple seeds or paraphrases of the same template do not create independent samples.

## 6. Measurements and reporting rules

Report security, utility and operations separately:

- **Prohibited sink effects:** count/rate of prohibited effects observed at the sink, with an explicit denominator of eligible attack opportunities.
- **Attack success rate:** attack templates that achieve their defined prohibited objective; distinguish proposal success from sink-effect success.
- **Legitimate task completion/utility:** correct completion of benign tasks under the declared policy.
- **False blocks:** legitimate required operations denied or escalated unnecessarily; define the denominator from the trusted task manifest.
- **Latency:** policy decision, adapter/broker overhead and end-to-end workflow p50/p95/p99.
- **Cost:** model/tool token usage and provider charges only when actual usage and dated billing rates are available. Token totals alone are not dollar cost.
- **Recovery:** duplicate-effect rate, unresolved/indeterminate outcomes, time to reconcile, quarantine/recovery success and stale-authority success after revocation.
- **Coverage:** percentage of declared effect paths actually routed through tested enforcement points; separately list untested or bypassable routes.
- **Uncertainty:** per-family counts, confidence intervals, template-clustered analysis, invalid/failed/skipped runs and sensitivity bounds for indeterminate sink outcomes.

The six-point protocol requires frozen templates, a declared primary estimand and denominator, randomization/reset rules, a disjoint pilot, simulation-based power/interval-coverage analysis and independent-template analysis. Thirty independent templates is only a minimum eligibility threshold for further review; it is not automatic statistical power.

## 7. Current Phase A completion status

| Element | Status as of this audit | Work still required |
|---|---|---|
| **A0 — Baseline freeze** | Partially complete. The code baseline, current `main` head, latest CI/release-validation runs and current comparator register have been checked. | Freeze exact Python/package/runtime versions, OS/kernel/DB configuration, model/provider versions and all experiment dependency artifacts. |
| **A1 — Scope and policy** | Drafted. The six lifecycle stages, protected assets and initial attacker capabilities are mapped. A narrow AgentDojo workspace pilot candidate is specified separately. | Approve and freeze the primary research policy family, eligible action/effect set, identity/tenant/task assumptions and exclusions. The AgentDojo pilot is only a harness-validation slice and is not the six-stage primary policy. |
| **A2 — TCB and bypass map** | Initial source/documentation inventory completed for the main runtime, lifecycle controller, broker, memory/framework adapters and provider connectors. | Complete executable path coverage for the chosen agent profile; add explicit negative-control bypass attempts for each declared resource route and validate under the actual worker/broker OS identities. |
| **A3 — Sink and outcome oracle** | Existing local resource commit tests and protocol guidance provide starting points. The AgentDojo pilot uses its native task/security and utility oracle for a limited read-tool benchmark slice. | For the lifecycle effect study, freeze a common sink contract, receipt/state oracle, effect identity, idempotency/retry rules and treatment of uncertain commits. The AgentDojo oracle is not a destination-side write-commit receipt; a remote-provider sink is not currently implemented. |
| **A4 — Native comparators** | Documentary source register exists; all 16 external entries remain `D / not_run`. AgentDojo's official `tool_filter` is wired in the runner and its configuration is unit/integration tested; no live native benchmark run is recorded. A public Multi-CaMeL artifact has now been source-pinned, but not installed or executed. | Execute and review the bounded AgentDojo pilot if credentials and a spend cap are authorised. Smoke-test the pinned Multi-CaMeL artifact and separately pin/smoke-test CaMeL, Progent and AID-Guard native artifacts where reproducible. Do not use a project-owned simulator or PACA broker path as a substitute. |
| **A5 — Traces and metrics** | The six-point protocol defines metrics, trace fields and template-level statistical rules; the AgentDojo runner captures several per-condition usage, latency, utility and indeterminate fields. | Freeze the exact schema, estimand, denominators, randomization/order control, reset rules, template independence, uncertainty handling and billing evidence for the primary study. The current AgentDojo runner's fixed order and lack of run-level seed control restrict it to exploratory pilot use. |
| **A6 — Review and transition** | Not complete. | Obtain review/sign-off on the Phase A threat model, policies, adapter map, comparator eligibility and sink oracle before beginning confirmatory evaluation. |

This is an initial baseline audit, not a declaration that Phase A is complete. A0–A2 have useful groundwork, but the policy, executable bypass coverage, sink contract, native comparator reproductions and review gate remain open.

## 8. Phase A work items and exit criteria

| Work item | Required output | Exit criterion |
|---|---|---|
| **A0 — Freeze baseline** | Commit IDs, dependency/runtime versions, adapter inventory, current CI evidence, comparator register and evidence labels. | The tested code and documents refer to the same pinned baseline; historical snapshots are marked as historical. |
| **A1 — Freeze scope and policy** | Six-stage boundary, protected-resource inventory, principals/tenants/tasks/purposes, effect definitions, policy version and exclusions. | Each selected scenario has an unambiguous authorized and prohibited outcome. |
| **A2 — Map the TCB and bypass surface** | Data-flow diagram and per-stage matrix of entry points, mediators, raw alternatives, trust assumptions and denial evidence. | Every selected path has a named enforcement point and a negative-control bypass path, or is explicitly out of scope. |
| **A3 — Define the oracle and sink** | Test sink contract, before/after state, immutable receipt format, idempotency and uncertainty/recovery semantics. | A prohibited committed effect can be distinguished from a denial, failure-before-commit and unknown outcome. |
| **A4 — Freeze native comparator profiles** | Pinned artefact/release, native configuration, task compatibility, policy mapping, mediation point, exclusions and evidence level. | No hand-coded imitation is represented as a native comparator; unsupported comparisons are marked D/I or not eligible. |
| **A5 — Freeze experiment traces and metrics** | Versioned scenario schema, trace format, event taxonomy, denominators, invalid-run handling and analysis plan. | Every outcome can be reconstructed from the trace and sink evidence. |
| **A6 — Review and approve transition to experiments** | Phase A report with unresolved risks, reproducibility instructions and reviewer sign-off. | G0 in the six-point protocol is satisfied. G1 baseline work may then begin; G2 must reproduce a residual gap before a new PACA mechanism is justified. |

### Phase A exit does not mean

Phase A completion would not mean that PACA has passed the six-stage lifecycle experiment, demonstrated superiority, achieved complete mediation, validated production readiness or completed an independent security review. It means only that the testable research boundary, threat assumptions, baseline candidates, evidence rules and experiment artifacts are sufficiently precise to begin the next evaluation gates.

## 9. Existing documents and source-of-truth hierarchy

Use the following division of responsibility to prevent duplicate and contradictory status claims:

- [`security-roadmap.md`](security-roadmap.md): current implementation maturity, engineering gaps and release/claim discipline.
- [`SEVEN_REQUIREMENTS_STATUS.md`](SEVEN_REQUIREMENTS_STATUS.md): implementation/evidence status against seven security requirements.
- [`AGENT_LIFECYCLE_ENFORCEMENT.md`](AGENT_LIFECYCLE_ENFORCEMENT.md): exact scope of the current lifecycle controller and reference runtime.
- [`SIX_POINT_INDUSTRY_EVALUATION_PROTOCOL.md`](SIX_POINT_INDUSTRY_EVALUATION_PROTOCOL.md): comparator configuration, residual-gap rules, sinks, statistical analysis and G0–G6 gates.
- [`PHASE_A_AGENTDOJO_PILOT_PROFILE.md`](PHASE_A_AGENTDOJO_PILOT_PROFILE.md): narrow, exploratory AgentDojo workspace pilot; not a full lifecycle experiment.
- [`industry_comparator_matrix.json`](industry_comparator_matrix.json): machine-readable source/evidence register.
- [`POLICY_CONTINUITY_EVALUATION.md`](POLICY_CONTINUITY_EVALUATION.md): four continuity dimensions and PACA-managed request test contract.
- [`DIRECT_BYPASS_EVALUATION.md`](DIRECT_BYPASS_EVALUATION.md) and [`UNIX_BROKER_DEPLOYMENT.md`](UNIX_BROKER_DEPLOYMENT.md): actual bypass and Linux IPC boundaries.
- [`ADVERSARIAL_SECURITY_AUDIT_PHASE_1.md`](ADVERSARIAL_SECURITY_AUDIT_PHASE_1.md): historical PR #13/#14 source audit; not a current-main audit and not this lifecycle programme's Phase A.

**Evidence links:** [main CI run at the inspected head](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New/actions/runs/46117268580) and [release-validation run](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New/actions/runs/46117268588). The live AgentDojo benchmark job was skipped in that CI run. No comparator run or new lifecycle-effectiveness experiment was executed as part of this Phase A documentation audit.
