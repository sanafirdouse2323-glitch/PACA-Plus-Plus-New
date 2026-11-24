# Durable provenance, authenticated authority and mediated agent memory

**Scope:** PAC++ New only. This document describes the agent-lifecycle security research prototype. It does not add enterprise gateway functions to the separate `PACA-Plus-Plus` enterprise gateway repository.

## Status and design boundary

This milestone adds a durable reference implementation for information lineage, capability authority, selected memory operations, inter-agent messages, and two framework integration points. It is an implementation tranche, not a claim that arbitrary agents or every connector path are now protected.

The design keeps three distinct security questions separate:

1. **What information contributed to this value?** Answered by the information-lineage DAG and verified content digests.
2. **Who may act on this information, for which task and purpose, under which current policy?** Answered by the authenticated capability and policy registry.
3. **Which actual runtime path releases a value or performs an effect?** Answered only for adapters and framework hooks that are explicitly wired to the PACA runtime.

A label or SHA-256 digest is not an identity credential. A signed capability is not proof that the capability remains active. A policy decision is not enforcement unless the relevant value-release or effect path actually goes through the adapter.

## Durable information lineage

### `SQLiteProvenanceRepository`

`paca.durable.SQLiteProvenanceRepository` stores lineage metadata independently of memory values. It records immutable object/version pairs, deterministic node identifiers, parent edges, authority bindings and lineage revocation events.

The repository uses a file-backed SQLite database, schema versioning, WAL mode, full synchronous writes, foreign-key constraints, a busy timeout and transactional `BEGIN IMMEDIATE` writes. A node and its parent edges are committed in one transaction. An object/version pair is immutable: replaying identical metadata is idempotent; reusing the identity with different metadata is rejected. Reopening the repository reconstructs and revalidates the graph before returning ancestry. The reconstructed parent edges are cross-checked against the separately persisted SQL edge table before revocation traversal; a mismatch fails closed rather than silently trusting either representation.

The repository intentionally rejects `:memory:` databases because they cannot establish restart safety. It is a **single-host storage implementation**, not a multi-host consensus service, distributed transaction coordinator, tamper-proof hardware log or replication protocol. Database directories and backups must be protected by the host deployment.

### Separate memory value store

`SQLiteMemoryValueStore` stores canonical JSON values in a separate file-backed database. A value write first records its lineage metadata and authority binding, then writes the immutable value bytes. This ordering prefers a metadata-only orphan after a crash over a value that can be retrieved without lineage metadata. It is not a cross-database atomic transaction; reconciliation and orphan cleanup are operational work still required.

The adapter recomputes the canonical JSON SHA-256 digest before accepting a write and after fetching a value. A mismatch causes a lineage revocation event and an error rather than returning the bytes. The digest detects a mismatch between the stored value and the trusted metadata; it does not independently prove that a connector supplied truthful source content.

## Trusted connector and derivation boundary

`TrustedConnectorAdapter` assigns a fixed connector identity, source class, tenant, sensitivity and integrity label from constructor configuration. Those values are not accepted from the model as part of the ingested content. Its default integrity classification is untrusted. A deployment may configure a trusted source only when the connector's authentication and content handling justify that decision.

Connector authentication, provider account selection, tenant mapping, source version identifiers and transport integrity remain part of the adapter's trusted computing base. The included adapter is a reference interface; it is not a production integration for Gmail, Microsoft Graph, Slack, a vector database or any other provider.

`TrustedMemoryAdapter` mediates reads, writes, summaries and compaction:

- A write requires a valid signed `mem_write` capability, matching tenant and purpose, a content digest calculated from the exact value, and an immutable lineage node.
- A derived write requires complete explicit parent references. Each input must identify exactly one persisted value/version, and its canonical bytes must match that node's immutable content digest. The current signed capability must also authorize reading every source under the active tenant, purpose, inherited authority and configured application metadata policy; a previously obtained `Arg` is not a lasting authorization. The supplied label must not upgrade integrity or reduce sensitivity, source origins, tenant lineage or unknown-tenant state. Source policy, authority and revocation are rechecked after persistence. Combined or unpersisted transformations must first be written as their own derived node.
- A read authenticates the capability and checks its object scope before metadata lookup. It reconstructs ancestry, checks each ancestor's tenant, purpose, revocation and bound authority, then applies the configured metadata policy to every ancestor. Only after those checks does it fetch the value bytes, verify the digest and re-check active authority, revocation state and the configured application policy before returning an `Arg`. A policy change during the value-store fetch therefore fails closed before the value is returned.
- Metadata-only disclosures use the same lineage, tenant, inherited-authority and configured policy checks. In particular, LangGraph `list_namespaces` and `ListNamespacesOp` batch filters are applied before policy evaluation, so an unrelated restricted namespace does not break an authorized filtered listing. A namespace whose stored object is denied by the application memory policy is not disclosed. Metadata enumeration does not fetch value bytes; it consumes one durable memory-read budget unit for each object whose metadata it discloses.
- Summarisation and compaction create new immutable derived nodes. They do not erase the source references simply because the new text is shorter or model-generated.

The metadata policy callback is mandatory for a successful read; a missing callback defaults to deny. The callback must use trusted policy state and must not infer authorization from model-written metadata.

## Authenticated capabilities and active policy state

### Issuer and token envelope

`HMACCapabilityAuthority` issues versioned, audience-bound, HMAC-SHA-256 capability envelopes. The signed payload binds the issuer, key identifier, intended audience, issuance time, typed authority record, role, call and delegation limits, and tool pins. The authority record binds principal, tenant, task, purpose, normalized action/target grants, expiry, policy epoch, parent identifier and parent-chain digest.

Issuance requires a mandatory `identity_verifier(principal, tenant)` callback. It must consult a trusted identity system and prove that the requesting issuer may act for that principal in that tenant. A test callback that returns true for a name is only a fixture; it is not authentication suitable for deployment.

**The included HMAC scheme is a shared-secret research mechanism, not OAuth, OIDC, a public-key JWT profile or a production KMS integration.** Any verifier that holds the HMAC key can also mint credentials. Production deployment requires issuer/verifier key separation, protected key storage, rotation and an independently authenticated issuer service. These features are not implemented in this tranche. The aggregate-quota branch increments the capability-envelope schema version to 2; version-1 envelopes are rejected rather than silently interpreted without the new immutable quota field.

### Durable policy epoch, revocation and budgets

`SQLiteAuthorityRegistry` persists immutable authority records, the monotonic global policy epoch, revocation events, per-capability usage counters and a separate tenant/task-wide aggregate call counter.

- Advancing the policy epoch invalidates all credentials issued under the previous epoch.
- Revoking an authority makes it inactive. Active-state validation walks the recorded parent chain, so revoking a parent also invalidates every delegated descendant without rewriting every descendant row.
- Delegation is accepted only from an active parent; it preserves tenant, task and purpose, restricts expiry and grants, requires a matching delegate target, and cannot broaden parent tool pins or quotas.
- Parent fan-out and delegation-call counters are updated transactionally with child registration. Per-capability operation counts are consumed transactionally, so verifying the same signed token repeatedly does not reset its own budget.
- The separate `task_usage` table enforces one aggregate `max_task_calls` budget for each authenticated `(tenant, task_id)` pair. All root capabilities and delegated descendants in that task share the same counter; reissuing a root capability does not reset it, and another tenant reusing the task ID has an independent counter.
- A root capability sets the immutable task ceiling with `max_task_calls` (default 100 in this reference issuer). Delegated capabilities inherit that ceiling and cannot change it. Creating a child capability, protected memory operation, message send/receive and protected runtime effect each consume one task-wide unit as well as the applicable per-capability unit. Root capability issuance itself does not consume an operation unit.
- Task quota reservation and per-capability usage updates run in the same `BEGIN IMMEDIATE` SQLite transaction. The counter survives restart and coordinates cooperating processes sharing that one local database file; it is not a multi-host or distributed-consensus quota service.
- Authority registry schema version 4 introduces the aggregate quota. An empty older registry can be upgraded automatically. A populated version-3-or-older registry is refused at startup because historic counters cannot safely establish a task-wide baseline; an operator-reviewed offline migration is required, with no guessed quotas or silent usage reset.
- Missing or inconsistent usage state, an unknown authority, an expired credential, a stale epoch or a revocation causes failure rather than a process-local fallback.
- The authority loader verifies that each SQL `parent_id` edge matches the parent identifier inside the canonical immutable authority record. The recursive revocation query uses that SQL edge; disagreement therefore fails closed before active-state decisions.
- The optional `SQLiteOperationLedger` used by the reference monitor separately scopes task-wide strike/quarantine, destination fan-out state and operation-history records by a deterministic SHA-256 key over the authenticated `(tenant, task_id)` pair. Operation-history rows also retain the tenant explicitly. A task-history query requires both tenant and task ID; the unfiltered history API is reserved for a trusted ledger administrator. Two tenants reusing a task ID do not share counters or task-filtered history. This audit/monitor ledger is separate from the aggregate operation quota in `SQLiteAuthorityRegistry`; it does not itself enforce the delegated-tree quota.
- The current operation-ledger schema is version 3. Task-filtered history requires both tenant and task ID, and every returned row has its stored tenant/task hash recomputed and compared with its persisted scope before disclosure; inconsistent rows fail closed. Older populated or structurally inconsistent ledgers do not have trustworthy tenant ownership for their task counters and audit rows; startup fails closed and requires an operator-reviewed offline migration. The implementation does not guess ownership, reassign history, or reset counters/tokens. Only an empty legacy schema may be recreated automatically.

The epoch is global to this reference registry. Fine-grained policy partitions, distributed consistency, quorum writes, high-availability failover, and event delivery to remote policy enforcement points are not implemented. The new task-wide quota is limited to this same-host SQLite reference registry; it does not close the separate distributed quota/consistency gap.

## Revocation of information derived from revoked authority or sources

Information and authority have different graphs and different revocation semantics.

- **Authority revocation** invalidates descendants through their parent chain. A lineage node written under an authority carries a durable authority binding. Reading that node or its derived descendants checks all inherited authority bindings and refuses release if any is inactive.
- **Information revocation** records a root node as revoked. The repository follows parent-to-child edges, so the root and every previously stored derived descendant are considered revoked. New summaries and compacted memories cannot be derived from a revoked parent.
- **Integrity failure** (the retrieved bytes do not match the recorded digest) quarantines the affected lineage by revoking that node. Descendants become unavailable through the same ancestry traversal.

This is logical unavailability, not secure physical deletion. It does not erase replicas, model-provider logs, checkpoints, embeddings, caches, exports or external copies. Those stores require their own deletion and retention mechanisms.

## Memory and multi-agent runtime integration

### LangGraph long-term store

`paca.integrations.langgraph.PACAProvenanceLangGraphStore` implements LangGraph's `BaseStore` sync and async store interface. It mediates `put`, `get`, `search`, `list_namespaces` and `delete` through the PACA memory adapter. Each write requires a trusted `provenance_provider` callback that returns complete `Arg` dependencies. Updating an existing logical key must include the prior version as a provenance dependency. The store does not guess which model context or tool results contributed to a value.

The initial implementation supports structured namespace search and filters. Semantic/vector search, vector index configuration and TTL are explicitly unsupported and fail rather than silently accepting and ignoring those options. Delete is logical lineage revocation, not physical erasure.

LangGraph's long-term `BaseStore` and its graph checkpointer serve different purposes. This integration wraps the long-term store only. The branch also provides a separate optional adapter for the official PostgreSQL checkpointer, documented in `POSTGRES_CHECKPOINT_AND_LIFECYCLE_MODEL.md`; that adapter does **not** instrument every checkpoint implementation, state snapshot, interrupt/resume payload or external persistence layer. Other providers and runtime paths require separate adapters and tests.

### LangChain tool middleware

`PACALangChainToolMiddleware` implements the current synchronous and asynchronous `AgentMiddleware.wrap_tool_call` hooks. It requires trusted callbacks that provide the current signed capability and map the actual registered tool call to an action-specific PACA `Request`. The request must include a typed tool manifest. The middleware checks that the requested tool identity matches the registered tool and that the manifest hash is pinned in the authenticated capability; it then routes the call through `PACAAgentRuntime`. A denied, unpinned, mismatched or revoked call does not invoke the tool handler.

The middleware does not infer a tool's side effects from its name or description. The trusted request factory must map each tool's complete effect contract, arguments, resource labels and provenance. The adapter fingerprints the JSON tool call before request construction, gives the trusted request factory a disposable request snapshot, rejects mutation of that snapshot or the caller's original tool-call/state during construction, and checks the call and registered manifest again immediately before invoking the original framework handler. The downstream handler receives a separate request snapshot with a deep-copied tool-call payload, copied tool object and deep-copied graph state; later mutation of the caller's request cannot change the arguments or state used by a suspended async handler. The framework runtime/context/store/config objects are not deep-copied because they can contain non-copyable execution services; they remain trusted application dependencies and must not be model-controlled or mutated concurrently. The trusted request factory must explicitly account for any injected runtime context or store state that can influence consequential tool behavior. With LangChain's middleware composition, PACA must be registered as the innermost/last tool-call middleware immediately before the actual ToolNode; any middleware ordered after PACA could still rewrite the call downstream and would be outside this check. It cannot prove that a trusted request factory semantically mapped the raw tool arguments correctly; that callback remains part of the trusted computing base. An unmapped tool must fail closed. A tool invocation made outside the configured middleware or through another client, callback, subprocess, network path or direct Python reference is outside this integration's guarantee.

### Signed inter-agent envelopes

`HMACAgentMessageCodec` provides a small authenticated message envelope for the reference runtime and is bound to the same `TrustedMemoryAdapter` instance used by the runtime. It binds the exact canonical message value to one immutable versioned lineage node by recomputing and checking that node's content digest on both send and receive. The referenced node carries the ancestry for the value; callers must persist transformed values through `TrustedMemoryAdapter.write_derived` before sending them. A bare `derive()` result or a payload that reuses source references for different bytes is rejected. The sender requires both a recipient-specific `send_agent_message` grant and current `mem_read` authority/policy for the payload. The receiver requires both a sender-specific `receive_agent_message` grant and current `mem_read` authority/policy before the value is returned. The one-time receive receipt is consumed before memory-read authorization so replay attempts do not repeatedly burn the recipient's memory-read budget; when a fresh message is denied by recipient memory policy, that receipt remains consumed and the sender must issue a new envelope after the policy/authority issue is resolved. Thus an envelope or messaging grant does not itself confer memory access. The codec also binds sender, recipient, task, purpose and authority, validates the full source ancestry, and refuses revoked or incomplete lineage. Each envelope carries a random message identifier; the authority registry records a durable receiver receipt and rejects a second delivery of the same message to the same principal/tenant/task, including after process restart. It is a PACA-specific message format, **not an implementation of MCP, A2A or another standardized agent-communication protocol**.

### Runtime and effect boundary

`PACAAgentRuntime` joins authenticated authority, memory, messages and a PACA monitor. Its sync and async effect methods compare the request capability with the verified signed credential, require the effect's tool manifest to match a signed tool pin, obtain a monitor decision and verify its effect token, durably consume the call budget, and re-check active authority immediately before invoking the supplied executor.

Before a monitor decision is accepted, the runtime snapshots the request and validates every lineage-bearing argument against exactly one persisted value/version: the argument's canonical bytes must match the immutable node digest, its label must cover the full ancestry, and current tenant, purpose, revocation, inherited authority and application metadata policy must allow use. A `resource_lineage_refs` entry likewise requires a stored node, an explicit resource label that covers its ancestry, and current policy authorization. Incomplete lineage and uncommitted multi-reference derivations fail closed. The monitor and executor receive the frozen request snapshot, not the caller's mutable request object. These lineage checks and active authority are repeated immediately before synchronous executor entry, and again after the async executor factory returns but before its body is awaited. The synchronous runtime rejects awaitable and generator results. The asynchronous runtime accepts only an unstarted native coroutine and rejects Tasks/Futures, started coroutines, nested deferred results, and generators/async generators rather than returning work that could execute later outside PACA. The async executor factory's synchronous portion must be side-effect-free; the consequential operation belongs inside the returned coroutine. A Task may already have started before a factory returns it, so executor callbacks and their scheduling behavior remain trusted application code.

A remote side effect cannot be made atomic with a local SQLite revocation registry. The destination service must independently validate the current authority at commit time, or the deployment must provide an equivalent resource-side transaction/lease protocol. A check immediately before a remote call only narrows the race; it does not eliminate a time-of-check/time-of-use window across systems.

## Threat assumptions and deployment cautions

The prototype assumes the issuer identity callback, connector identity/configuration, provenance provider, policy callback, middleware installation, tool manifest mapping, database handles and signing keys are controlled by trusted application code. An `Arg` with no lineage references is treated as an untracked literal/input and therefore still depends on the trusted ingress and labeling boundary; runtime code cannot infer a missing source reference from the value itself. This is not automatic capture of every prompt, model context, framework variable or tool dependency. The DNS/IP-pinned TLS helper also rejects caller-supplied SSL contexts that disable certificate-chain or hostname verification; callers must still revalidate every redirect and avoid transports that perform a second hostname resolution. The Linux `SecureRoot` helper opens targets with `openat2` beneath a preconfigured root, checks the inode through an `O_PATH` descriptor before opening file data, rejects symlinks and hard-linked files, uses nonblocking opens so a FIFO cannot stall validation before it is rejected, and serializes descriptor use against close. The root must still be an administrator-controlled, appropriately mounted workspace (including `nodev` where relevant); this helper is not a process sandbox and does not stop callers using other filesystem APIs. A Python object boundary is not a sandbox. If model-controlled code can import the raw value store, access the SQLite files, read HMAC keys, execute arbitrary SQL or invoke tools outside the middleware, it can bypass the wrappers. Untrusted code and tools must run in a separately enforced OS/process/container boundary with credentials unavailable to that code.

SQLite WAL and transactions provide durable local coordination for cooperating processes on one host. They do not provide multi-host linearizability or distributed revocation delivery. Database files and their containing directories must be protected with host ACLs, encrypted backups and controlled service identities. File mode 0600 is a best-effort POSIX permission setting, not a substitute for deployment controls.

## Validation included in the branch

The focused lifecycle suite is `tests/test_durable_lifecycle.py`. It covers:

- restart-safe lineage reconstruction, immutable object/version conflicts and missing-parent rollback;
- concurrent idempotent insertion;
- connector labels, retrieval-before-value-release checks, fail-closed policy callbacks and policy revalidation after value fetch;
- lineage propagation through summary and compaction;
- source and ancestor revocation, including revocation of previously stored derived information;
- digest tampering and quarantine;
- HMAC tampering, audience mismatch, expiry, identity callback rejection and policy-epoch invalidation;
- delegated-descendant revocation, parent fan-out and call-budget persistence;
- concurrent operation-budget consumption and resistance to token re-verification resets;
- sender/recipient authorization, payload-to-lineage digest binding on send and receive, independent sender/receiver memory-read grant and application-policy checks, and inter-agent replay rejection;
- runtime effect rejection for forged argument bytes, incomplete lineage, downgraded labels, stale source authority, denied application policy and resource-label mismatch; frozen request snapshots, async revocation rechecks, and rejection of deferred/lazy executor results;
- synchronous and asynchronous effect revocation races;
- LangGraph `BaseStore` operations, metadata-only namespace listing under a denying application policy, explicit rejection of unsupported vector index configuration, and a compiled `StateGraph` using the PACA store;
- LangChain synchronous and asynchronous tool middleware, handler suppression on deny, tool identity mismatch, framework-call and graph-state mutation during request construction and after authorization, async handler isolation from the caller's mutable request state, and revocation before the handler.

The optional `langgraph` dependency extra is pinned and receives a dedicated CI job. Its async BaseStore entry points snapshot mutable operation/value/filter inputs before worker-thread handoff and preserve LangGraph's `NOT_PROVIDED` TTL sentinel by identity; inputs that cannot be deep-copied fail closed. `tests/test_secure_execution_primitives.py` separately exercises Linux `openat2` path constraints, hard-link and FIFO rejection, and pinned DNS/TLS behavior. Core persistence and authority tests remain runnable without the optional framework packages.

These are deterministic reference tests, not an independent penetration test, production security certification or proof that arbitrary Python/framework execution cannot bypass the integration. The current suite does not establish provider-backed mailbox/chat connectors, a production identity provider, KMS, distributed registry, checkpoint instrumentation for providers other than the optional PostgreSQL adapter, protocol-standard agent-to-agent messaging, or resource-side atomic remote effect validation.

## External interface references

- [LangGraph long-term memory stores](https://docs.langchain.com/oss/python/langgraph/stores)
- [LangGraph store base API](https://reference.langchain.com/python/langgraph/store/base/BaseStore)
- [LangChain agent middleware](https://docs.langchain.com/oss/python/langchain/agents/middleware)
- [LangChain `AgentMiddleware.wrap_tool_call`](https://reference.langchain.com/python/langchain/agents/middleware/types/AgentMiddleware/wrap_tool_call)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/)
- [Model Context Protocol Authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

---

**Maturity statement:** PAC++ New remains a research prototype. This milestone implements durable local lineage, an authenticated reference capability issuer and registry, mediated reference memory, a custom signed message codec, and two framework adapters. It does not establish complete or production-grade security for an arbitrary LLM-agent lifecycle.
