# Durable provenance, authenticated authority and mediated agent memory

**Scope:** PACA++ New only. This document describes the agent-lifecycle security research prototype. It does not add enterprise gateway functions to the separate PACA++ repository.

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
- A derived write requires complete explicit parent references. It checks that referenced nodes exist and are not revoked, that purpose is preserved, and that the supplied label does not upgrade integrity or reduce sensitivity, source origins, tenant lineage or unknown-tenant state.
- A read authenticates the capability and checks its object scope before metadata lookup. It reconstructs ancestry, checks each ancestor's tenant, purpose, revocation and bound authority, then applies the configured metadata policy to every ancestor. Only after those checks does it fetch the value bytes, verify the digest and re-check active authority and revocation state before returning an `Arg`.
- Summarisation and compaction create new immutable derived nodes. They do not erase the source references simply because the new text is shorter or model-generated.

The metadata policy callback is mandatory for a successful read; a missing callback defaults to deny. The callback must use trusted policy state and must not infer authorization from model-written metadata.

## Authenticated capabilities and active policy state

### Issuer and token envelope

`HMACCapabilityAuthority` issues versioned, audience-bound, HMAC-SHA-256 capability envelopes. The signed payload binds the issuer, key identifier, intended audience, issuance time, typed authority record, role, call and delegation limits, and tool pins. The authority record binds principal, tenant, task, purpose, normalized action/target grants, expiry, policy epoch, parent identifier and parent-chain digest.

Issuance requires a mandatory `identity_verifier(principal, tenant)` callback. It must consult a trusted identity system and prove that the requesting issuer may act for that principal in that tenant. A test callback that returns true for a name is only a fixture; it is not authentication suitable for deployment.

**The included HMAC scheme is a shared-secret research mechanism, not OAuth, OIDC, a public-key JWT profile or a production KMS integration.** Any verifier that holds the HMAC key can also mint credentials. Production deployment requires issuer/verifier key separation, protected key storage, rotation and an independently authenticated issuer service. These features are not implemented in this tranche.

### Durable policy epoch, revocation and budgets

`SQLiteAuthorityRegistry` persists immutable authority records, the monotonic global policy epoch, revocation events and per-capability usage counters.

- Advancing the policy epoch invalidates all credentials issued under the previous epoch.
- Revoking an authority makes it inactive. Active-state validation walks the recorded parent chain, so revoking a parent also invalidates every delegated descendant without rewriting every descendant row.
- Delegation is accepted only from an active parent; it preserves tenant, task and purpose, restricts expiry and grants, requires a matching delegate target, and cannot broaden parent tool pins or quotas.
- Parent fan-out and delegation-call counters are updated transactionally with child registration. Per-capability operation counts are consumed transactionally, so verifying the same signed token repeatedly does not reset its own budget.
- These are per-capability counters, not a single task-wide aggregate quota across the whole delegation tree. A parent can create several independently budgeted children up to its fan-out limit; total descendant operations are not charged back against one shared task counter in this tranche.
- Missing or inconsistent usage state, an unknown authority, an expired credential, a stale epoch or a revocation causes failure rather than a process-local fallback.

The epoch is global to this reference registry. Fine-grained policy partitions, distributed consistency, quorum writes, high-availability failover, and event delivery to remote policy enforcement points are not implemented.

## Revocation of information derived from revoked authority or sources

Information and authority have different graphs and different revocation semantics.

- **Authority revocation** invalidates descendants through their parent chain. A lineage node written under an authority carries a durable authority binding. Reading that node or its derived descendants checks all inherited authority bindings and refuses release if any is inactive.
- **Information revocation** records a root node as revoked. The repository follows parent-to-child edges, so the root and every previously stored derived descendant are considered revoked. New summaries and compacted memories cannot be derived from a revoked parent.
- **Integrity failure** (the retrieved bytes do not match the recorded digest) quarantines the affected lineage by revoking that node. Descendants become unavailable through the same ancestry traversal.

This is logical unavailability, not secure physical deletion. It does not erase replicas, model-provider logs, checkpoints, embeddings, caches, exports or external copies. Those stores require their own deletion and retention mechanisms.

## Memory and multi-agent runtime integration

### LangGraph long-term store

`paca.integrations.langgraph.PACAProvenanceLangGraphStore` implements LangGraph's `BaseStore` sync and async store interface. It mediates `put`, `get`, `search`, `list_namespaces` and `delete` through the PACA memory adapter. Each write requires a trusted `provenance_provider` callback that returns complete `Arg` dependencies. Updating an existing logical key must include the prior version as a provenance dependency. The store does not guess which model context or tool results contributed to a value.

The initial implementation supports structured namespace search and filters. Semantic/vector search and TTL are explicitly unsupported and fail rather than silently using an unmediated path. Delete is logical lineage revocation, not physical erasure.

LangGraph's long-term `BaseStore` and its graph checkpointer serve different purposes. This integration wraps the long-term store; it does **not** replace or transparently instrument every checkpoint, state snapshot, interrupt/resume payload or external persistence layer. Those require separate adapters and tests.

### LangChain tool middleware

`PACALangChainToolMiddleware` implements the current synchronous and asynchronous `AgentMiddleware.wrap_tool_call` hooks. It requires trusted callbacks that provide the current signed capability and map the actual registered tool call to an action-specific PACA `Request`. The request must include a typed tool manifest. The middleware checks that the requested tool identity matches the registered tool and that the manifest hash is pinned in the authenticated capability; it then routes the call through `PACAAgentRuntime`. A denied, unpinned, mismatched or revoked call does not invoke the tool handler.

The middleware does not infer a tool's side effects from its name or description. The trusted request factory must map each tool's complete effect contract, arguments, resource labels and provenance. An unmapped tool must fail closed. A tool invocation made outside the configured middleware or through another client, callback, subprocess, network path or direct Python reference is outside this integration's guarantee.

### Signed inter-agent envelopes

`HMACAgentMessageCodec` provides a small authenticated message envelope for the reference runtime. It preserves the value, labels and lineage references, binds sender, recipient, task, purpose and authority, checks both sender/receiver grants, validates the full source ancestry, and refuses revoked or incomplete lineage. Each envelope carries a random message identifier; the authority registry records a durable receiver receipt and rejects a second delivery of the same message to the same principal/tenant/task, including after process restart. It is a PACA-specific message format, **not an implementation of MCP, A2A or another standardized agent-communication protocol**.

### Runtime and effect boundary

`PACAAgentRuntime` joins authenticated authority, memory, messages and a PACA monitor. Its sync and async effect methods compare the request capability with the verified signed credential, require the effect's tool manifest to match a signed tool pin, obtain a monitor decision and verify its effect token, durably consume the call budget, and re-check active authority immediately before invoking the supplied executor.

A remote side effect cannot be made atomic with a local SQLite revocation registry. The destination service must independently validate the current authority at commit time, or the deployment must provide an equivalent resource-side transaction/lease protocol. A check immediately before a remote call only narrows the race; it does not eliminate a time-of-check/time-of-use window across systems.

## Threat assumptions and deployment cautions

The prototype assumes the issuer identity callback, connector identity/configuration, provenance provider, policy callback, middleware installation, tool manifest mapping, database handles and signing keys are controlled by trusted application code. A Python object boundary is not a sandbox. If model-controlled code can import the raw value store, access the SQLite files, read HMAC keys, execute arbitrary SQL or invoke tools outside the middleware, it can bypass the wrappers. Untrusted code and tools must run in a separately enforced OS/process/container boundary with credentials unavailable to that code.

SQLite WAL and transactions provide durable local coordination for cooperating processes on one host. They do not provide multi-host linearizability or distributed revocation delivery. Database files and their containing directories must be protected with host ACLs, encrypted backups and controlled service identities. File mode 0600 is a best-effort POSIX permission setting, not a substitute for deployment controls.

## Validation included in the branch

The focused lifecycle suite is `tests/test_durable_lifecycle.py`. It covers:

- restart-safe lineage reconstruction, immutable object/version conflicts and missing-parent rollback;
- concurrent idempotent insertion;
- connector labels, retrieval-before-value-release checks and fail-closed policy callbacks;
- lineage propagation through summary and compaction;
- source and ancestor revocation, including revocation of previously stored derived information;
- digest tampering and quarantine;
- HMAC tampering, audience mismatch, expiry, identity callback rejection and policy-epoch invalidation;
- delegated-descendant revocation, parent fan-out and call-budget persistence;
- concurrent operation-budget consumption and resistance to token re-verification resets;
- sender/recipient authorization and inter-agent message integrity;
- synchronous and asynchronous effect revocation races;
- LangGraph `BaseStore` operations and a compiled `StateGraph` using the PACA store;
- LangChain synchronous and asynchronous tool middleware, handler suppression on deny, tool identity mismatch and revocation before the handler.

The optional `langgraph` dependency extra is pinned and receives a dedicated CI job. Core persistence and authority tests remain runnable without the optional framework packages.

These are deterministic reference tests, not an independent penetration test, production security certification or proof that arbitrary Python/framework execution cannot bypass the integration. The current suite does not establish a provider-backed connector, production identity provider, KMS, distributed registry, native LangGraph checkpoint instrumentation, protocol-standard agent-to-agent messaging, or resource-side atomic remote effect validation.

## External interface references

- [LangGraph long-term memory stores](https://docs.langchain.com/oss/python/langgraph/stores)
- [LangGraph store base API](https://reference.langchain.com/python/langgraph/store/base/BaseStore)
- [LangChain agent middleware](https://docs.langchain.com/oss/python/langchain/agents/middleware)
- [LangChain `AgentMiddleware.wrap_tool_call`](https://reference.langchain.com/python/langchain/agents/middleware/types/AgentMiddleware/wrap_tool_call)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/)
- [Model Context Protocol Authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

---

**Maturity statement:** PACA++ New remains a research prototype. This milestone implements durable local lineage, an authenticated reference capability issuer and registry, mediated reference memory, a custom signed message codec, and two framework adapters. It does not establish complete or production-grade security for an arbitrary LLM-agent lifecycle.
