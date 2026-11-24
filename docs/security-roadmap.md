# PAC++ New: Agent-lifecycle implementation status and roadmap

This document is subordinate to [the Agent-Lifecycle Security Research Programme](AGENT_LIFECYCLE_SECURITY_RESEARCH.md), which defines the research scope, related work, proposed UCAUM model, threat model, hypotheses, evaluation plan and claim limits.

**Project boundary:** PAC++ New focuses on LLM-agent lifecycle security. The separate PACA++ repository focuses on the enterprise authorization gateway. Do not merge their codebases, roadmaps or completion claims.

## Current status

### Existing foundation on main

- Provenance labels and explicit label propagation through `Arg` and `derive()`.
- Task-scoped capabilities with action/target grants, expiry, call/fan-out limits, tool pins and parent identifiers.
- A policy monitor for selected memory, tool, delegation, file and egress actions.
- A deterministic simulator with selected memory read/write and effect paths.
- An AgentDojo tool-executor adapter, a task-scoped mapper for 14 workspace read/search operations, and a paired benchmark runner.
- Author-defined deterministic scenarios for selected risk classes.

These are partial building blocks. They do not constitute complete lifecycle mediation.

## Phase-1 branch additions

The open cumulative PR [#13](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New/pull/13) adds the following supporting components:

- Optional `SQLiteOperationLedger` for persisted capability fingerprints, budgets, decision records and single-use token state. Task-wide strike/quarantine, egress fan-out and task-filtered operation-history records are tenant-scoped; task-history queries require both tenant and task ID, while unfiltered history is an administrator view. Populated or inconsistent older ledgers fail closed pending an operator-reviewed offline tenant mapping; schema version 3 verifies the tenant/task scope hash on every returned audit row, never guesses ownership or resets existing state. It is local-file/multi-process coordination, not a multi-host database or a memory-provenance graph.
- Linux `openat2`-based `SecureRoot` and DNS/IP-pinned socket/TLS primitives. `SecureRoot` rejects symlink escapes, hard-linked files and FIFO stalls before releasing a descriptor. These primitives are not yet wired into every real tool implementation and do not replace an OS/process sandbox.
- A bounded TLA+ authorization protocol model. It does not model the full agent lifecycle or prove Python implementation refinement.
- Additional provenance and fail-closed generic-tool-dispatch hardening.

These components may support the lifecycle research but are not the central research contribution. Their existence must not be described as enterprise-gateway functionality or complete agent security.

### Sandbox / external-containment evaluation tranche

The branch also adds `tests/test_sandbox_boundary_cases.py` and [the containment evaluation protocol](CONTAINMENT_EVALUATION.md). The tests cover a test-only cross-session artifact handoff that must preserve untrusted provenance and a cross-tenant memory lookup that must be denied before the value is fetched. The existing `SandboxScoped` comparator is deliberately a simplified, hand-authored allow-list model; it is not a test of NVIDIA OpenShell, NVIDIA Sentry or an OpenAI-hosted environment.

No actual vendor sandbox integration, host-kernel escape test, hardware side-channel test, independent watchdog, credential broker or production shared-memory adapter is included in this tranche.

### Phase-B typed lineage semantics on the research branch

The branch now includes separate, typed in-memory information and authority histories:

- `LineageNode` and `ProvenanceGraph` record object/version identity, content digest, source, source class, labels, parents, transformations and optional purpose. Parent-first insertion and monotonic label checks reject unknown parents, conflicting object/version records, trust upgrades and loss of inherited provenance metadata.
- `Arg.lineage_refs` carries optional node references through the existing `derive()` helper; `lineage_incomplete` is set when a derived value includes an untracked dependency. The explicit graph transformation method rejects incomplete inputs and creates a new versioned node.
- `AuthorityLineage` and `AuthorityLineageGraph` record immutable issuer/principal/tenant/task/purpose/scope/expiry/policy-epoch/parent metadata. Each child binds the digest of its complete parent chain; parent-first insertion checks that digest, purpose and tenant/task continuity, non-decreasing policy epoch, expiry attenuation and conservative target-grant subset relations.
- `Request.digest` binds information and resource lineage references plus the authority record. The mutable capability's exact ID and parent ID, as well as its principal, tenant, task, scope and expiry, are checked against its immutable authority snapshot before a digest is produced.

**Phase-B limits:** this tranche established typed lineage and authority semantics only. It did not, by itself, persist the graphs, authenticate issuer identity, maintain active policy state, revoke descendants, instrument hidden model context or integrate a real memory store. The following durable lifecycle tranche addresses a defined subset of those gaps; the remaining limitations are documented separately.

### Durable lifecycle, memory and runtime integration tranche

The changes from the former lifecycle and aggregate-quota branches are now merged into `main`. The current implementation includes [the durable lifecycle security design and implementation record](DURABLE_LIFECYCLE_SECURITY.md):

- `SQLiteProvenanceRepository`: file-backed, schema-versioned, transactional, append-only object/version lineage metadata with parent edges, restart reconstruction, integrity validation, authority bindings and recursive lineage revocation. It is a single-host SQLite reference, not a distributed repository.
- `SQLiteMemoryValueStore` and `TrustedMemoryAdapter`: a distinct immutable JSON value store; fixed-identity connector ingress; signed-scope memory writes; metadata/tenant/purpose/lineage/revocation checks before value fetch; post-fetch content-digest verification; and explicit summary/compaction derivations.
- `SQLiteAuthorityRegistry` and `HMACCapabilityAuthority`: signed audience-bound version-2 capability envelopes, mandatory trusted principal/tenant identity callback and separate task-context verifier (principal, tenant, task and purpose), persistent monotonic global policy epoch, revocation propagation through delegated parent chains, durable per-capability call/fan-out counters, and persistent inter-agent message replay receipts. The task callback must consult trusted orchestrator state; an allow-all or caller-controlled callback provides no task binding. The now-merged aggregate-quota implementation adds an immutable `max_task_calls` ceiling and an atomic shared counter keyed by authenticated tenant plus task ID. It charges delegated child creation, protected memory operations, message send/receive and protected runtime effects across all roots and descendants. The default ceiling is 100; callers may set it when issuing a root capability, and descendants inherit it unchanged. The SQLite registry remains single-host; optional `PostgresAuthorityRegistry` shares authority, revocation, capability usage, task-wide quota, message receipts and local resource-commit state across clients using one authoritative primary. HMAC remains a shared-secret reference mechanism.
- **Shared PostgreSQL authority backend (phase 4):** PostgresAuthorityRegistry implements the existing registry contract for authority lineage, epoch/revocation, per-capability counters, tenant/task aggregate quota, message receipts and local resource-commit state. Mutations serialize across clients on one PostgreSQL primary using a transaction-scoped registry-table lock. This removes per-process SQLite authority/quota namespaces for workers configured against that same primary. Multi-primary, rollback-safe failover, provenance/value-store replication and the Monitor operation ledger remain open.
- **Asymmetric issuer/verifier keys (phase 3):** Ed25519CapabilityAuthority supports a private-key issuer and public-key-only verifier for capability envelopes and resource-commit permits, with explicit algorithm and key ID binding. HMAC remains for compatibility. KMS/HSM custody, key-ring rotation/overlap/revocation, authenticated public-key distribution, OIDC/workload identity and issuer-service isolation remain open.
- **Read-only provider connectors (phase 4):** OAuth refresh plus Gmail, Microsoft Graph mail (Mail.ReadBasic by default; Mail.Read only for explicit body access), Slack conversation-history and Qdrant search adapters; scoped requests, fixed HTTPS origins, redirect refusal, Graph nextLink host validation, bounded JSON, source object/version capture and persistence as untrusted digest-bound provenance. Qdrant now requires a trusted tenant binding, injects a mandatory server-side tenant payload filter, and verifies the tenant marker on every returned point and again at memory ingress. CI uses mocked HTTP only. Live account binding, Qdrant write-side tenant-marker integrity, KMS-backed refresh-token rotation, webhook/deletion sync, incremental sync and all provider writes/resource commit fencing remain open.

- `HMACAgentMessageCodec`: authenticated PACA-specific sender/recipient envelopes bound to the shared memory adapter; preserve labels and lineage, bind exact payload bytes to one immutable lineage-node digest, require sender and recipient memory-read grants plus current application policy in addition to message grants, validate full ancestry and reject duplicate delivery after restart. Transformed values must be persisted with their own lineage node before sending. This is not MCP or A2A protocol interoperability.
- **Phase-2 replay hardening:** authenticated sequential message replays are short-circuited by an indexed durable receipt lookup before sender-authority and provenance traversal. The transactional receipt insertion and quota charge remain the concurrency-safe enforcement point. Concurrent duplicate work, first-delivery ancestry bounds and ingress rate limiting remain open.
- **Trusted effect ingress (phase 3):** every argument to a protected `PACAAgentRuntime` effect must carry a persisted value/version lineage reference; untracked caller-created arguments, including caller-asserted trusted labels, fail before monitor evaluation and effect execution. Static effect inputs must also be captured explicitly. This remains a same-process adapter trust boundary until worker/process isolation is enforced.
- **Process isolation adapter (phase 3):** optional `DockerSandbox`/`DockerSandboxExecutor` executes action-mapped commands in a digest-pinned, network-disabled, read-only, non-root, resource-limited container and does not transfer authority credentials. It is opt-in; the runtime does not yet enforce it for all executors, and every consequential resource mutation still requires a resource-side commit fence.
- **Resource-side commit fencing (phase 3):** opt-in strict runtime mode for `write_file`/`mem_write` issues a short-lived one-use permit bound to request/action/target/payload; `SQLiteFencedResourceExecutor` validates current authority, revocation, epoch, grant, replay nonce and both quotas in the same SQLite transaction that writes the local resource version. This gives a serial commit/revocation order only for the local single-host reference store. Remote provider commits, other actions and mandatory deployment enforcement remain open.
- **Strict consequential-monitor profile:** the standard `Monitor` exposes `assert_consequential_safe()`, which rejects all policy ablations, checks required rule semantics, prevents destination-clearance overrides more permissive than the packaged baseline, preserves packaged protected-path patterns and disallows a weaker quarantine threshold. `PACAAgentRuntime` validates this at construction and immediately before each protected effect; AgentDojo validates it at adapter construction and before each tool dispatch. Research ablations remain simulator-only.
- `PACAAgentRuntime`: synchronous and asynchronous reference effect paths that compare request authority to the signed credential, bind the action to a pinned tool manifest, validate the monitor decision/token, bind lineage-bearing arguments to exact persisted value digests and conservative ancestry labels, authorize resource-lineage metadata, freeze the request snapshot, and recheck active authority and memory policy immediately before executor entry. Default mode charges the effect budget before calling a trusted application executor. Optional `require_resource_commit_fence=True` mode is restricted to `write_file`/`mem_write`, defers the effect charge to the local atomic resource transaction, and rejects any executor other than the runtime-bound `SQLiteFencedResourceExecutor`. The synchronous path rejects awaitable/generator results; the async path requires an unstarted native coroutine and rejects Tasks/Futures, nested deferred results and lazy generators. Untracked arguments remain dependent on trusted ingress/labeling; the async executor factory must not start effects or schedule Tasks before returning its coroutine.
- `PACAProvenanceLangGraphStore`: a LangGraph `BaseStore` adapter for mediated long-term memory, with explicit provenance-provider callbacks, protected read/write/delete, structural search and unsupported TTL/vector search and index configuration failing closed rather than being silently ignored.
- `PACALangChainToolMiddleware`: synchronous and asynchronous LangChain `AgentMiddleware` hooks that verify actual registered tool identity and a signed tool-manifest pin before routing a mapped PACA request through the runtime.

The focused lifecycle suite exercises restart and concurrency, object/version immutability, durable indexed-identity tampering, memory read-before-fetch ordering, application-policy enforcement for LangGraph namespace metadata including pre-authorization `ListNamespacesOp` filtering, taint through summarisation/compaction, derived-memory exact-value digest and current-authority checks, source and delegated-authority revocation, authority parent-edge tampering, derived-memory invalidation, integrity quarantine, epoch changes, token tampering/audience/expiry, tenant-isolated persistent task counters and task-filtered audit history, populated legacy-ledger fail-closed behavior, payload-to-lineage message digest binding, sender/recipient memory-read grant and application-policy enforcement, runtime effect rejection for forged/stale/weakly labelled provenance, resource metadata checks, immutable request snapshots, async revocation rechecks, rejection of scheduled/nested Tasks and deferred generator results, persistent budgets, message authorization, real LangGraph store use in a compiled StateGraph, and synchronous/asynchronous LangChain tool interception with tool-call and graph-state mutation checks and handler suppression.

**Remaining limits:** the Gmail, Microsoft Graph, Slack and Qdrant adapters are read-only, mock-tested reference connectors rather than live production tenant integrations; all relevant framework entry points must be explicitly wired; LangGraph checkpoint persistence is not intercepted by the long-term store adapter; the custom message format is not a standard inter-agent protocol; HMAC keys and identity callbacks remain trusted host responsibilities; untracked request arguments still rely on trusted ingress/label assignment; SQLite is single-host; external tools and destinations can bypass Python wrappers unless isolated; and cross-system remote effect commit is not atomic with local revocation. These are stated precisely in `DURABLE_LIFECYCLE_SECURITY.md`.

## Lifecycle coverage gaps

| Lifecycle surface | Current evidence | Work still required |
|---|---|---|
| Input / observation | Simulated receive/ingest; AgentDojo tool outputs | Trusted source identity, typed input channels, complete connector coverage |
| Provenance / derivation | Typed lineage DAG plus durable SQLite object/version nodes, parent edges, authority bindings, restart reconstruction and recursive lineage revocation | Trusted provider identity/content adapters, full context/checkpoint instrumentation, distributed storage and independent validation |
| Memory | Separate durable JSON value store; mediated connector ingress, retrieval, summarisation and compaction; LangGraph BaseStore adapter with read-before-fetch checks | Provider-specific production adapters, native checkpoint instrumentation, vector search/TTL, external cache/replica deletion and complete write-channel inventory |
| Planning / decision | Action requests are checked by monitor | Instrumented plan/decision transitions; plans treated as proposals; revalidation when state changes |
| Delegation | HMAC-authenticated audience-bound capability envelopes, trusted identity callback, durable global policy epoch and revocation, parent-chain revocation, grant/expiry/purpose attenuation, per-capability budgets and an atomic tenant/task-wide quota shared across descendants in the local SQLite reference registry | Production IdP/OIDC workload identity, KMS/HSM custody and rotation, multi-primary consistency, rollback-safe failover and distributed provenance/value/operation-ledger state, and resource-side enforcement across independent agents |
| Communication | PACA-specific signed agent-message envelopes preserve label/lineage and check sender/recipient grants, tenant/task/purpose and revocation | Standard MCP/A2A interoperability, provider transport authentication, channel lifecycle and remote replay/retry semantics |
| Tool/effect | AgentDojo adapter plus LangChain sync/async middleware; pinned tool manifests, durable usage checks, and an opt-in local SQLite resource commit fence for `write_file`/`mem_write` | Full inventory of all tools/callbacks/subprocesses, mandatory isolation, remote provider-side commit fencing and distributed authority state |
| Execution containment | Linux `openat2` path, hard-link and FIFO tests; DNS/IP/TLS pinning checks; a generic toy sandbox comparator | Pinned OpenShell / OpenAI environment integrations, full process/network mediation, redirect revalidation, credential brokering, supervisor-failure and host-escape tests |
| Revocation / recovery | Global monotonic policy epoch, recursive delegated-descendant revocation, information-DAG descendant invalidation, pre-fetch denial and digest-mismatch quarantine | Distributed revocation delivery, replica/checkpoint erasure, automated recovery/replay and cross-system atomicity |
| Formal assurance | Bounded token/approval/tenant/delegation model on PR #13 | Lifecycle state model, adversarial transitions, crash/concurrency assumptions and implementation refinement |
| Evaluation | Self-authored simulator and limited AgentDojo integration | Reproduced baselines plus ASB, AgentDyn, MPBench and multi-agent/lifecycle-specific experiments |

## Recommended implementation sequence

1. **Freeze the threat model and transition inventory.** Identify every place where data, authority, agent identity, policy state or external effects enter/change/leave the system.
2. **Specify UCAUM semantics before adding more infrastructure.** Define provenance objects, authority objects, capability ordering, purpose, expiry, policy epochs, revocation and declassification.
3. **Build a lifecycle event interface.** Instrument input, retrieval, derivation, memory write/read/compaction, planning, delegation, communication, tool execution and recovery.
4. **Implement provenance continuity in real state stores.** Preserve source and transformation lineage across memory persistence, retrieval and cross-agent messages.
5. **Implement authority continuity.** Add dynamic revocation, descendant invalidation, task/purpose binding and revalidation at consequential transitions.
6. **Integrate actual effect paths.** Use the phase-1 filesystem/network primitives where applicable, but only after mapping and testing each real tool's full effect contract.
7. **Extend formal verification.** Model memory, provenance, delegation, communication, revocation, stale state and effect commit. Connect each abstract transition to executable tests.
8. **Evaluate against external baselines.** Reproduce compatible public benchmarks first, then add delayed-activation and lifecycle-composition cases. Evaluate OpenShell and a specifically identified OpenAI-hosted or self-hosted Agents API environment only after real adapters and pinned configurations exist. Keep model calls, raw results and error denominators explicit.

## Acceptance gates

A lifecycle surface is not complete because a helper or unit test exists. It is complete only for a declared scope when:
- the relevant real framework paths are inventoried;
- enforcement occurs before protected data release or effect execution;
- alternate paths and bypasses are tested;
- state and provenance survive restart and handoff where required;
- revocation and recovery semantics are exercised;
- utility impact and failure cases are measured; and
- claims match the evidence and assumptions.

## Current maturity statement

PAC++ New remains a **research prototype for provenance-aware, capability-based authorization across selected LLM-agent lifecycle boundaries**. It is not a complete lifecycle security product, production agent runtime, enterprise gateway or independently validated security guarantee.


## Lifecycle tranche: PostgreSQL checkpoint mediation and bounded formal model

PAC++ New now includes an optional adapter around LangGraph's PostgreSQL checkpointer. Checkpoint state and pending task writes receive separate immutable provenance/evidence records. The adapter authenticates and checks the PACA evidence path before returning provider state, compares provider data to the evidence, and tenant-scopes provider thread IDs. The integration requires the application to supply trusted, complete provenance callbacks for checkpoint and pending-write inputs.

The PostgreSQL service is the actual checkpoint provider. The PACA authority registry, lineage graph, and value evidence remain the existing local SQLite stores. They do not share one transaction or distributed consensus protocol. Provider credentials and raw saver objects must remain in a trusted service boundary; callers with direct database access can bypass a Python wrapper. The current implementation wraps the synchronous PostgreSQL saver; async calls are run through worker threads rather than a native async pool. Provider PendingWrite tuples omit task_path, so the adapter rejects ambiguous reuse of a task ID across multiple paths for one checkpoint. Provider-returned checkpoint/thread/namespace/parent identities are checked against PACA evidence, latest lookup and listing mirror the provider's descending checkpoint-ID order and strict `before` cursor semantics while validating thread/namespace scope, and thread deletion revokes both checkpoint and pending-write evidence under separate deletion scopes. Post-provider authorization rechecks narrow but do not eliminate the non-atomic cross-store race.

A new bounded TLA+ lifecycle model covers memory, checkpoint and pending-write lineage; authority delegation and attenuation; tenant, purpose and task continuity; lineage and authority revocation; expiry and policy epochs; a shared task-wide operation budget; and an abstract remote effect whose authorization is checked at the commit transition. This is an abstract finite-state model, not a refinement proof of the Python code, PostgreSQL behavior, host isolation, distributed consistency or remote resource enforcement.

A purpose-continuity defect in derived-memory validation was fixed: every input parent is now checked for purpose compatibility before a derived value is written. Regression tests exercise the denial path and document the raw value-store bypass as a deliberate negative control.

See:
- POSTGRES_CHECKPOINT_AND_LIFECYCLE_MODEL.md
- DIRECT_BYPASS_EVALUATION.md

Remaining gates: live provider-account and tenant-identity binding and validation (the current connectors are read-only mock-HTTP adapters, not live customer-account integrations), provider webhook/deletion and incremental synchronization, KMS/HSM-backed private-key and refresh-token custody, authenticated public-key distribution and key-ring rotation/revocation, production workload identity and OIDC validation, a distributed authority/evidence registry that preserves the tenant/task-wide quota across hosts, a native async provider adapter, process/container isolation tests with attacker-controlled code, and destination-side authorization at remote commit.
