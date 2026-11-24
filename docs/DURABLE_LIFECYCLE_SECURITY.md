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

### Read-only provider adapters and provenance capture

The optional `paca.integrations.providers` module provides `GmailConnector`, `MicrosoftGraphMailConnector`, `SlackHistoryConnector` and `QdrantVectorConnector`. Install with `pip install "paca-plus-plus[providers]"`. Gmail uses the read-only Gmail messages.list/messages.get API and its Gmail readonly scope. Microsoft Graph uses the `/me/messages` collection. Metadata-only mode requests `Mail.ReadBasic`; `read_body=True` explicitly requires the broader `Mail.Read` scope and selects body fields only in that mode. It rejects any `@odata.nextLink` that is not the exact Graph hostname/messages collection. Slack uses conversations.history with an explicitly selected history scope for the conversation type. Qdrant uses points/search and an injected API-key provider. The Qdrant adapter requires a trusted `tenant_id` at construction, adds a mandatory server-side payload filter (default key `tenant_id`, configurable as a dotted payload path), keeps any caller filter nested under that mandatory predicate, always requests the payload, and verifies the exact tenant value in every returned point before creating a capture. `ProviderCapture.persist()` also refuses to persist a Qdrant record when the embedded tenant does not match the configured `TrustedConnectorAdapter.tenant`. The host must source `tenant_id` from authenticated identity—not model input—and the Qdrant write-side permission model must prevent one tenant from forging another tenant's payload marker. A per-tenant collection and credential boundary is stronger where shared-collection payload ownership cannot be guaranteed.

`OAuth2RefreshTokenProvider` requires a fixed HTTPS token endpoint and trusted client/refresh-token configuration. It checks requested scopes against the configured consent grant and token-response scope, caches tokens until expiry, refuses token redirects and requires a persistence callback if the authorization server rotates a refresh token. Do not store the client secret or refresh token in source code, model context or logs; use an encrypted secret store and an authenticated callback for rotation.

Each response is represented by a `ProviderCapture` containing a fixed connector identity, provider object ID, provider version metadata, and a canonical record digest. Its `persist()` method requires the matching `TrustedConnectorAdapter` configured with `integrity="untrusted"` and `source_class="external_content"`; the actual provider record is persisted through the existing memory adapter and bound to its exact content digest. This object is for trusted host integration code only and must not be exposed as a model-facing arbitrary-ingress endpoint.

CI uses mocked HTTP transports; it does not connect to real provider accounts. The new Qdrant tenant filter and returned-payload checks are exercised with mocks; they do not authenticate the configured tenant or protect a Qdrant collection from a writer that can forge tenant payload fields. Tenant/user identity mapping, token subject validation, consent administration, refresh-token KMS storage, webhook/delete propagation, full incremental sync, provider audit trails and remote write/commit protocols remain deployment/integration work. These connectors do not send messages, update mail, write Slack messages or mutate vector collections.


Connector authentication, provider account selection, tenant mapping, source version identifiers and transport integrity remain part of the adapter's trusted computing base. The included adapter is a reference interface; it is not a production integration for Gmail, Microsoft Graph, Slack, a vector database or any other provider.

`TrustedMemoryAdapter` mediates reads, writes, summaries and compaction:

- A write requires a valid signed `mem_write` capability, matching tenant and purpose, a content digest calculated from the exact value, and an immutable lineage node.
- A derived write requires complete explicit parent references. Each input must identify exactly one persisted value/version, and its canonical bytes must match that node's immutable content digest. The current signed capability must also authorize reading every source under the active tenant, purpose, inherited authority and configured application metadata policy; a previously obtained `Arg` is not a lasting authorization. The supplied label must not upgrade integrity or reduce sensitivity, source origins, tenant lineage or unknown-tenant state. Source policy, authority and revocation are rechecked after persistence. Combined or unpersisted transformations must first be written as their own derived node.
- A read authenticates the capability and checks its object scope before metadata lookup. It reconstructs ancestry, checks each ancestor's tenant, purpose, revocation and bound authority, then applies the configured metadata policy to every ancestor. Only after those checks does it fetch the value bytes, verify the digest and re-check active authority, revocation state and the configured application policy before returning an `Arg`. A policy change during the value-store fetch therefore fails closed before the value is returned.
- Metadata-only disclosures use the same lineage, tenant, inherited-authority and configured policy checks. In particular, LangGraph `list_namespaces` and `ListNamespacesOp` batch filters are applied before policy evaluation, so an unrelated restricted namespace does not break an authorized filtered listing. A namespace whose stored object is denied by the application memory policy is not disclosed. Metadata enumeration does not fetch value bytes; it consumes one durable memory-read budget unit for each object whose metadata it discloses.
- Summarisation and compaction create new immutable derived nodes. They do not erase the source references simply because the new text is shorter or model-generated.

The metadata policy callback is mandatory for a successful read; a missing callback defaults to deny. The callback must use trusted policy state and must not infer authorization from model-written metadata.

## Authenticated capabilities and active policy state
### PostgreSQL authority registry for shared-primary deployments

The module paca.postgres_authority provides PostgresAuthorityRegistry, a PostgreSQL-backed implementation of the authority-registry API using psycopg 3. Supply a PostgreSQL DSN and pass the resulting registry to the existing HMAC or Ed25519 capability authority:

    from paca.authority_runtime import HMACCapabilityAuthority
    from paca.postgres_authority import PostgresAuthorityRegistry

    registry = PostgresAuthorityRegistry(postgres_dsn, timeout=15.0)
    issuer = HMACCapabilityAuthority(
        registry,
        issuer_id="paca-issuer",
        key_id="paca-key-1",
        key=issuer_secret,
        audience="paca-runtime",
        identity_verifier=identity_verifier,
        task_context_verifier=task_context_verifier,
    )

The optional dependency is installed with pip install "paca-plus-plus[postgres]". Schema version 5 stores authority records, policy epoch/events, revocations, per-capability usage, task-wide usage, message receipts and local resource-commit receipts/values in the same PostgreSQL database. Existing populated version-3-or-older registries are refused because their historical per-task quota baseline cannot be inferred. Version-4 registries can be upgraded transactionally to add resource commit state. A version-5 database missing its resource-commit tables fails closed rather than recreating empty replay state.

To preserve the existing API's explicit transaction boundaries, every mutating operation begins a PostgreSQL transaction and acquires a transaction-scoped SHARE ROW EXCLUSIVE lock across registry tables. This serializes cooperating writers across independent clients connected to the same primary. The design is deliberately conservative and can constrain write throughput; performance and lock-wait behaviour must be load-tested for the deployment.

**Deployment limits:** every issuer and worker for a tenant/task must use the same authoritative primary and schema/search path. Use TLS and least-privilege credentials; the role needs schema migration privileges during controlled deployment, and runtime roles should have only the required DML permissions after migration. This backend does not implement multi-primary writes, read-replica consistency, automatic failover rollback detection, quorum consensus or tamper-evident audit export. Do not promote a replica that may have lost acknowledged authority, quota, revocation or receipt commits. Provenance metadata, memory values and the optional Monitor operation ledger remain separate SQLite components and are not made distributed by this registry.


### Issuer and token envelope

`HMACCapabilityAuthority` issues versioned, audience-bound, HMAC-SHA-256 capability envelopes. The signed payload binds the issuer, key identifier, intended audience, issuance time, typed authority record, role, call and delegation limits, and tool pins. The authority record binds principal, tenant, task, purpose, normalized action/target grants, expiry, policy epoch, parent identifier and parent-chain digest.

Issuance requires two mandatory callbacks. `identity_verifier(principal, tenant)` must consult a trusted identity system and prove that the requesting issuer may act for that principal in that tenant. `task_context_verifier(principal, tenant, task_id, purpose)` must consult orchestrator-owned task state and prove that the principal is authorised for that exact tenant/task/purpose. Both callbacks run for root issuance and delegated issuance (the latter uses the task and purpose inherited from the authenticated parent). Do not implement the task callback as an allow-all predicate or derive its decision solely from caller-supplied task IDs. Test callbacks are fixtures only, not authentication suitable for deployment.

**HMAC remains a shared-secret research/compatibility mechanism, not OAuth, OIDC or a production KMS integration.** Any HMAC verifier holding the secret can also mint credentials. The repository now also includes Ed25519CapabilityAuthority: an issuer instance accepts a raw private seed (and its matching public key), while a verifier instance accepts only the raw public key and cannot issue capability tokens or resource-commit permits. Both capability envelopes and resource-commit permits bind the explicit signature_algorithm and key_id; legacy version-2 HMAC capability tokens without an algorithm field remain verifiable for compatibility.

This is a cryptographic role-separation primitive, not a complete production key-management system. Private seed protection, KMS/HSM integration, key-ring rotation/overlap/revocation, authenticated public-key distribution, workload identity and OIDC claim validation remain deployment requirements and are not implemented. The identity/task callbacks remain trusted application integrations. The aggregate-quota branch increments the capability-envelope schema version to 2; version-1 envelopes are rejected rather than silently interpreted without the new immutable quota field.

### Durable policy epoch, revocation and budgets

`SQLiteAuthorityRegistry` persists immutable authority records, the monotonic global policy epoch, revocation events, per-capability usage counters and a separate tenant/task-wide aggregate call counter.

- Advancing the policy epoch invalidates all credentials issued under the previous epoch.
- Revoking an authority makes it inactive. Active-state validation walks the recorded parent chain, so revoking a parent also invalidates every delegated descendant without rewriting every descendant row.
- Delegation is accepted only from an active parent; it preserves tenant, task and purpose, restricts expiry and grants, requires a matching delegate target, and cannot broaden parent tool pins or quotas.
- Parent fan-out and delegation-call counters are updated transactionally with child registration. Per-capability operation counts are consumed transactionally, so verifying the same signed token repeatedly does not reset its own budget.
- The separate `task_usage` table enforces one aggregate `max_task_calls` budget for each authenticated `(tenant, task_id)` pair. All root capabilities and delegated descendants in that task share the same counter; reissuing a root capability does not reset it, and another tenant reusing the task ID has an independent counter.
- A root capability sets the immutable task ceiling with `max_task_calls` (default 100 in this reference issuer). Delegated capabilities inherit that ceiling and cannot change it. Creating a child capability, protected memory operation, message send/receive and protected runtime effect each consume one task-wide unit as well as the applicable per-capability unit. Root capability issuance itself does not consume an operation unit.
- Task quota reservation and per-capability usage updates run in the same `BEGIN IMMEDIATE` SQLite transaction. The counter survives restart and coordinates cooperating processes sharing that one local database file; it is not a multi-host or distributed-consensus quota service.
- Authority registry schema version 4 introduced the aggregate quota. An empty older registry can be upgraded automatically. A populated version-3-or-older registry is refused at startup because historic counters cannot safely establish a task-wide baseline; an operator-reviewed offline migration is required, with no guessed quotas or silent usage reset. Schema version 5 adds local resource-commit receipts and resource-value rows; existing version-4 registries are upgraded transactionally.
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

For the standard `Monitor`, consequential runtime construction and every protected effect call validate `assert_consequential_safe()`. The validator rejects all policy-check ablations and verifies that the required packaged rule semantics (including cross-tenant, sensitivity, SSRF, untrusted-control and approval rules) have not been removed, duplicated or weakened. It also rejects destination clearances above the packaged defaults, missing packaged protected-path patterns and a quarantine threshold weaker than the default; stricter configuration is allowed. `PacaToolsExecutor` applies the same validation at construction, immediately before authorization, and again before an approval retry. Research ablations remain available in the deterministic simulator, not in these consequential adapters. Custom monitor implementations that do not expose this validator, along with application callbacks that map identity, provenance, resource metadata or tool effects, remain trusted application components; the validator does not authenticate arbitrary Python code.


Before a monitor decision is accepted, the runtime snapshots the request and validates every lineage-bearing argument against exactly one persisted value/version: the argument's canonical bytes must match the immutable node digest, its label must cover the full ancestry, and current tenant, purpose, revocation, inherited authority and application metadata policy must allow use. A `resource_lineage_refs` entry likewise requires a stored node, an explicit resource label that covers its ancestry, and current policy authorization. Incomplete lineage and uncommitted multi-reference derivations fail closed. The monitor and executor receive the frozen request snapshot, not the caller's mutable request object. These lineage checks and active authority are repeated immediately before synchronous executor entry, and again after the async executor factory returns but before its body is awaited. The synchronous runtime rejects awaitable and generator results. The asynchronous runtime accepts only an unstarted native coroutine and rejects Tasks/Futures, started coroutines, nested deferred results, and generators/async generators rather than returning work that could execute later outside PACA. The async executor factory's synchronous portion must be side-effect-free; the consequential operation belongs inside the returned coroutine. A Task may already have started before a factory returns it, so executor callbacks and their scheduling behavior remain trusted application code.

The repository includes an opt-in local resource-side commit fence for the `write_file` and `mem_write` actions. `PACAAgentRuntime(require_resource_commit_fence=True)` requires the exact runtime-bound `SQLiteFencedResourceExecutor`. In HMAC mode, the runtime defaults the resource verifier to the issuer instance, retaining the shared-secret trust limitation. With an Ed25519 issuer, strict mode requires a separate public-key-only `Ed25519CapabilityAuthority` passed as `resource_commit_verifier`; construction checks that the verifier uses the same authority database and matching issuer ID, key ID, audience and signature algorithm, and rejects a verifier that holds the Ed25519 private signing key. The runtime signs the short-lived one-use permit with its private-key issuer, while the resource executor verifies it with the separate public-key-only instance. Both must coordinate through the same local SQLite authority database; this is key-role separation, not a separate-host or remote-provider commit protocol. The permit binds the request digest, action, target, payload digest, authority, tenant/task/purpose, policy epoch and nonce. The resource adapter verifies the permit and `SQLiteAuthorityRegistry.commit_fenced_resource_write` checks current authority/revocation/epoch, target grant, replay nonce and per-capability plus aggregate task budgets in the same `BEGIN IMMEDIATE` transaction that persists the resource version. This creates a serial ordering against revocation in the same local SQLite database; the regression suite tests revocation-before-commit denial, concurrent commit/revocation ordering, and private-key issuer to public-key-only resource-verifier operation.

This guarantee is limited to the local single-host SQLite reference data plane. The strict mode is opt-in and currently supports only `write_file` and `mem_write`; default application executors are not automatically fenced. A remote Gmail, Microsoft Graph, Slack or vector-database call cannot participate in the local SQLite transaction. The destination service must independently validate current authorization at commit time or offer an equivalent conditional write/fencing/idempotency protocol. A check immediately before a remote call only narrows the time-of-check/time-of-use window; it does not eliminate it.

## Threat assumptions and deployment cautions

The prototype assumes the issuer identity callback, connector identity/configuration, provenance provider, policy callback, middleware installation, tool manifest mapping, database handles and signing keys are controlled by trusted application code. Protected runtime effects reject every `Arg` without lineage references; framework/tool inputs must be captured by a trusted ingress adapter and persisted as digest-bound values before use. A caller-created label, including `integrity="trusted"`, is not source authentication. This is not automatic capture of every prompt, model context, framework variable or tool dependency. The DNS/IP-pinned TLS helper also rejects caller-supplied SSL contexts that disable certificate-chain or hostname verification; callers must still revalidate every redirect and avoid transports that perform a second hostname resolution. The Linux `SecureRoot` helper opens targets with `openat2` beneath a preconfigured root, checks the inode through an `O_PATH` descriptor before opening file data, rejects symlinks and hard-linked files, uses nonblocking opens so a FIFO cannot stall validation before it is rejected, and serializes descriptor use against close. The root must still be an administrator-controlled, appropriately mounted workspace (including `nodev` where relevant); this helper is not a process sandbox and does not stop callers using other filesystem APIs. A Python object boundary is not a sandbox. The repository now provides an opt-in `DockerSandbox`/`DockerSandboxExecutor` adapter with a digest-pinned image, no network, read-only root, non-root identity, dropped capabilities, seccomp, cgroup memory/CPU/PID limits, bounded I/O and timeout. It sends no authority tokens or provider credentials to the worker and performs no host mounts. The adapter is not yet mandatory in `PACAAgentRuntime`; applications can still choose an in-process executor or bypass middleware unless the deployment routes every untrusted tool through this boundary. The Docker daemon, image and host kernel remain trusted, and resource-side commit fencing is a separate required control.

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
