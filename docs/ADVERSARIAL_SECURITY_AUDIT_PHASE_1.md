# Adversarial Security Audit — Phase 1

> **Historical snapshot:** this document records the earlier code state reviewed against PRs #13 and #14. Those changes have since been merged. The findings below have not all been revalidated against current `main`; use [the current implementation roadmap](security-roadmap.md) and [direct-bypass evaluation](DIRECT_BYPASS_EVALUATION.md) for current boundaries. This source-level review is not an independent penetration test or security certification.

**Scope:** PAC++ New only, on top of the cumulative PR #13 branch and dependent PR #14 aggregate task-quota change.

**Audit type:** Source-level adversarial review of the integrated Python implementation and its stated trust boundaries. This is not an independent penetration test, a production deployment assessment, or a proof that all bypasses have been eliminated.

**Reviewed refs at audit start:**
- PR #13: `security/roadmap-phase-1` (head `fd32fc7abf22757c749ebfdfe2b28db81c31a8c0`)
- PR #14: `security/aggregate-task-quota` (head `f0786810f4910085fc51070fcad8e68ec45e6c44`)
- This audit branch is based on the PR #14 head, so it is dependent on both changes.

## 1. Confirmed implementation properties

The following properties were confirmed by source inspection; they should not be generalized beyond the paths named.

1. **Task-wide call accounting:** PR #14 stores one counter per authenticated `(tenant, task_id)` in `task_usage`. Delegation, mediated effects, message receipt, memory reads/writes and metadata disclosure charge through the durable authority registry paths. SQLite `BEGIN IMMEDIATE` transactions serialize updates on the same local database. Delegated authorities inherit the immutable `max_task_calls` value. The quota does not create a multi-host coordination protocol.
2. **Per-capability accounting remains separate:** `authority_usage` continues to track each authority's call and fan-out use. The aggregate task counter supplements rather than replaces these per-capability limits.
3. **Message replay receipt:** `consume_message` inserts the recipient replay receipt and charges the recipient's per-capability and task-wide counters in one SQLite transaction. A duplicate receipt or quota failure rolls the transaction back. The receipt key is principal + tenant + task + message ID, so alternate capability IDs for the same principal/task do not create a fresh receipt.
4. **Memory read checks:** the mediated memory read path checks authority, tenant/purpose, lineage ancestry, source-authority activity, application policy and content digests before returning values; it rechecks authority/policy/revocation after retrieval.
5. **Framework mediation is adapter-scoped:** LangGraph Store, LangChain AgentMiddleware and the PostgreSQL checkpoint wrapper mediate calls that actually pass through those configured adapters. They do not intercept arbitrary direct calls to underlying tools, database connections, raw stores or provider clients.
6. **Effect checks narrow but do not eliminate races:** the runtime revalidates authority and lineage immediately before executor entry. The executor's external side effect is not transactionally coupled to the SQLite revocation state.
7. **Formal verification scope:** the bounded TLA+ models are checked by TLC. They are not a refinement proof of the Python code, the database implementation, framework integration or a deployed system.

## 2. Findings and residual attack surfaces

### A-01 — Revocation is not atomic with external effect commit

**Severity:** High for consequential remote effects  
**Status:** Partially mitigated for local SQLite-backed resource writes; remote/provider effects remain open

The phase-3 resource-fencing branch adds an opt-in strict mode to `PACAAgentRuntime` and a `SQLiteFencedResourceExecutor` for the `write_file` and `mem_write` action paths. The runtime creates a short-lived, one-use HMAC commit permit bound to the capability authority ID, tenant, task, purpose, policy epoch, action, exact target, request digest, payload digest and nonce. The resource adapter verifies that permit, then calls `SQLiteAuthorityRegistry.commit_fenced_resource_write`.

The commit method performs all of the following in one `BEGIN IMMEDIATE` transaction on the same database used by `revoke()` and policy-epoch advancement: reloads and validates the authority DAG; checks current epoch, expiry and ancestor revocation; verifies the exact action/target grant; rejects replayed permit nonces; charges both per-capability and tenant/task-wide budgets; and writes the resource value/version and receipt. A deterministic concurrency test pauses a commit while it holds the SQLite write transaction and starts revocation concurrently. The write commits first and revocation serializes after it. A separate test revokes immediately before the resource transaction and verifies that no write or effect-budget charge occurs.

**Security guarantee:** within this single-host SQLite resource adapter, a resource commit and authority revocation have one database serialization order. A commit can complete before revocation, or it is rejected after revocation; the permit cannot be replayed to perform a second write. The effect-budget charge and resource write are committed or rolled back together.

**Residual impact:** this is an opt-in reference data plane supporting only `write_file` and `mem_write`. It does not make existing in-process executors safe by default, does not cover every action, and is not a remote resource-server protocol. Gmail, Microsoft Graph, Slack, vector databases and other external services do not share the local SQLite transaction. Those integrations need provider/destination-side conditional authorization, fencing/ETag or equivalent conditional commit semantics, plus idempotency and replay handling. In HMAC mode, the permit is symmetric and a verifier holding the shared secret can mint one; Ed25519 mode supports a public-key-only resource verifier, but does not add protected key custody, authenticated key distribution or key rotation. The local SQLite registry is single-host and assumes the database/issuer process are trusted.

**Required control:** make a destination-side commit fence mandatory for every consequential deployment action; implement provider-specific resource-side commit protocols for remote destinations; replace shared-secret permits with asymmetric issuer/verifier separation and protected key rotation; and validate multi-host semantics before distributed production claims.

### A-02 — Untracked literal arguments depend on trusted ingress

**Severity:** High when agent-controlled code can construct PACA values  
**Status:** Partially mitigated in the protected reference runtime; process trust boundary remains open

The phase-3 trusted-ingress branch changes `TrustedMemoryAdapter.authorize_argument` to reject every protected effect argument without a durable lineage reference. This includes caller-constructed `Arg` values whose `Label` claims trusted integrity, known origins or tenant provenance. Arguments must be captured and persisted through the configured trusted ingress adapter, and their canonical bytes must match the immutable lineage digest before an effect is authorized. The runtime rejects missing lineage before invoking the policy monitor, consuming the protected effect call budget, or entering the executor.

The regression suite covers trusted-looking, default-untrusted and caller-origin-claimed untracked arguments, and verifies that none reaches the monitor or executor. Framework integration tests construct their path arguments through the trusted ingress fixture rather than manually asserting trusted labels.

**Residual trust boundary:** Python code already running with access to the trusted connector, capability-token provider, filesystem and authority registry can still misuse those interfaces. A trusted ingress adapter must obtain source metadata from the provider/framework boundary; it must not merely relabel model-supplied bytes. Process isolation and provider-authenticated source capture remain necessary. Static literals that influence protected effects must also be registered as explicit, digest-bound inputs.

### A-03 — Framework/tool adapters do not cover alternative execution paths

**Severity:** High  
**Status:** Partially mitigated by an explicit Docker worker adapter; runtime-wide mandatory isolation remains open

The repository now includes `DockerSandbox` and `DockerSandboxExecutor`. The sandbox requires an immutable image digest and launches a worker with `--network=none`, a read-only root filesystem, a non-root UID, all Linux capabilities dropped, `no-new-privileges`, the default seccomp profile, private IPC, PID limits, memory/CPU limits, a no-exec/no-suid temporary filesystem, bounded stdin/stdout/stderr and a wall-clock timeout. The command is a trusted action-to-executable mapping; model input is passed as JSON arguments, never shell text. No host volume, device, Docker socket, capability token, grant set, authority record, signing key or provider credential is mounted or serialized into the worker.

The adapter can be supplied as the executor callback to `PACAAgentRuntime`. Its deterministic tests inspect the actual Docker command and verify the worker payload excludes authority material.

**Residual risk:** this adapter is opt-in, not a mandatory runtime policy. Existing Python executors, direct tool clients, framework callbacks, subprocesses, raw database clients and network/filesystem APIs remain possible if the application does not route them through the isolated executor. A worker can return a proposed result, but a consequential host-resource write still needs resource-side commit authorization. The Docker daemon, pinned image and host kernel remain trusted; the deployment must restrict access to the Docker socket and verify cgroup enforcement. This is not proof against kernel/container-runtime vulnerabilities.

**Required control:** make isolated execution mandatory for untrusted tool code in the production deployment profile, route all consequential mutations through a commit-fenced resource broker, pin and scan worker images, and test direct/bypass execution from an adversarial worker.

### A-04 — Async executor factory has an unenforceable synchronous-prefix assumption

**Severity:** High for integrations that start work before returning an awaitable  
**Status:** Open contract limitation

The async runtime accepts only a newly-created native coroutine and revalidates after the executor factory returns. This protects the coroutine body from starting before the recheck. It cannot undo side effects performed synchronously inside the executor factory before it returns that coroutine. The code therefore relies on the executor factory's synchronous portion being side-effect-free.

**Impact:** A badly-behaved or adversarial executor factory can start a thread, issue a request, schedule a callback, or perform a direct side effect before the second validation.

**Required control:** Treat executor factories as trusted code and enforce a narrow factory contract. Prefer a two-phase API in which PACA receives a pure operation descriptor, obtains a commit authorization/fencing token, and a trusted resource adapter performs the effect only after validating that token. Add adversarial tests for synchronous-prefix thread/task/network side effects.

### A-05 — Aggregate quota depends on trusted task identity and one shared registry

**Severity:** High if task IDs or registry selection are caller-controlled  
**Status:** Partially mitigated on the phase-2 task-context branch; production trust remains deployment-dependent.

The issuer now requires a separate `task_context_verifier(principal, tenant, task_id, purpose)` callback in addition to principal-to-tenant identity verification. It invokes that callback for root and delegated capability issuance after delegation scope has been derived from the parent record. The callback must consult trusted orchestrator/task-registry state and establish that the requested principal is an authorised participant in that exact tenant/task/purpose context. It must not merely accept caller-supplied identifiers or return true for all tasks.

**Residual impact:** The callback is application-supplied code; a permissive or compromised callback restores the original quota-splitting risk. Separate SQLite files or hosts still create separate quota namespaces.

**Required control:** Wire the callback to an authenticated orchestrator/service-owned task registry, protect its credentials and prevent agent-controlled code from invoking the issuer directly. For multi-host operation, move the authority/usage contract to a server database with transactional consistency and explicit failover semantics. The local callback contract reduces the API trust gap but does not itself deliver distributed quotas.

### A-06 — Message replay validation has an availability/rate-limit gap

**Severity:** Medium  
**Status:** Open hardening item

The phase-2 replay-hardening branch adds an indexed has_message_receipt(principal, tenant, task_id, message_id) pre-check after recipient-capability and envelope-MAC verification, recipient binding and bounded message-ID validation. A sequential duplicate is now rejected before sender-authority lookup, source-node loading, content-digest verification and provenance ancestry traversal. The check is read-only and is only an availability optimisation: the existing consume_message transaction remains authoritative, inserts the unique receipt and charges per-capability/task-wide quotas atomically, and therefore still rejects concurrent duplicate deliveries safely.

**Concurrency validation:** a deterministic two-thread regression forces both duplicate deliveries to pass the read-only pre-check before either reaches the receipt transaction. It verifies that exactly one delivery succeeds and that only one message-receive receipt plus its protected memory-read charge commits. This validates duplicate-delivery safety at the local SQLite transaction boundary; it does not bound the work both concurrent copies perform before that boundary.

**Impact after phase-2 change:** sequential authenticated replays no longer repeat the expensive lineage path. Concurrent copies can still both pass the read-only pre-check and perform validation before one loses at the transactional insert. First-time messages can still reference a large existing ancestry. There is still no explicit per-principal ingress rate limiter or bounded database-backed lineage traversal budget.

**Remaining required controls:** add per-principal/task ingress rate limits and a database-level bounded ancestry traversal for first-time messages; exercise concurrent replay floods and measure worst-case work. Do not describe this item as fully closed.

### A-07 — Message acceptance can consume a receipt before memory-read authorization succeeds

**Severity:** Medium (delivery/availability semantics)  
**Status:** Open behavior decision

The receive path commits `consume_message` before calling `authorize_argument`. If the recipient has a receive grant but lacks memory-read scope or the application policy denies the read, the receipt remains consumed and the message cannot be retried with that same message ID. This is fail-closed for replay/budget accounting, but it creates at-most-once delivery semantics even when downstream authorization fails.

**Impact:** A valid sender can cause a message to be irretrievably consumed for a recipient whose effective memory policy does not allow access, or during a transient policy denial.

**Required control:** Make the intended semantics explicit. If delivery should be retryable, separate an authenticated pending receipt from a completed receipt, or atomically coordinate receive authorization and receipt completion. Do not roll back replay protection merely to improve retries. Add tests for missing read grant, temporary policy denial, and successful retry policy.

### A-08 — Shared-secret HMAC and production identity/key management

**Severity:** High for multi-service production deployments  
**Status:** Partially mitigated by an Ed25519 issuer/verifier primitive; production key custody, rotation and identity integration remain open

The repository now includes Ed25519CapabilityAuthority, using a private-key-configured instance for issuance and a public-key-only instance for verification. Capability envelopes and resource-commit permits bind an explicit signature_algorithm and key_id; verifier-only instances cannot issue capabilities or resource permits. Tests cover public-key verification, denial of issuer methods on verifier-only instances, resource permit verification with only a public key, a complete strict local resource write using a private-key issuer and separate public-key-only resource verifier, wrong key ID, wrong audience, wrong public key, payload tampering and validly signed algorithm-downgrade rejection. HMAC remains available as the compatibility/reference mechanism, and legacy version-2 HMAC capability envelopes without an algorithm field remain verifiable.

**Impact after phase-3 change:** a service that receives only the Ed25519 public key can verify signatures without receiving the issuer's signing seed. This removes the shared-HMAC secret from the verifier trust boundary when deployments actually configure separate issuer and verifier instances.

**Residual risk:** the implementation accepts raw private seed bytes supplied by the application; it does not integrate KMS/HSM custody, encrypted key loading, a managed key ring, key ID rotation/overlap/revocation, automated certificate/public-key distribution, workload identity or OIDC provider verification. The existing identity_verifier and task_context_verifier callbacks are still trusted application interfaces, not a production IdP. A compromised issuer or private seed can still mint credentials. The separate monitor C13 effect-token mechanism is unchanged.

**Required control:** protect the Ed25519 private key using KMS/HSM or workload-bound signing, implement a versioned key ring with overlap and emergency revocation, distribute verifier public keys through authenticated configuration, and bind issuer calls to validated workload identity and authoritative tenant/task membership. Keep HMAC verifiers and keys out of production multi-service deployments.

### A-09 — Provider adapters require authenticated source capture and destination-side authorization

**Severity:** High for real-world provider data/effects  
**Status:** Partially mitigated by read-only provider connectors; production identity binding and remote effects remain open

The phase-4 provider branch adds read-only HTTP adapters for Gmail messages.list/messages.get, Microsoft Graph /me/messages with constrained nextLink handling and separate Mail.ReadBasic metadata-only versus explicit Mail.Read body access, Slack conversations.history, and Qdrant points search. OAuth2RefreshTokenProvider performs HTTPS refresh-token exchanges, verifies configured/granted scopes, caches short-lived bearer tokens, supports rotated refresh-token persistence callbacks and refuses token-endpoint redirects. Qdrant credentials are injected through a callable secret provider. Provider HTTP clients refuse redirects, enforce HTTPS (except explicitly allowed localhost for Qdrant development), cap response bytes, validate JSON responses and return sanitized errors. Microsoft Graph pagination accepts only the graph.microsoft.com messages collection origin/path; the token is never sent to an arbitrary nextLink host.

Each provider result is converted into a ProviderCapture carrying a fixed connector ID, provider object ID, provider version metadata and a canonical content version. Persisting that capture requires a matching TrustedConnectorAdapter configured as untrusted external content, and TrustedConnectorAdapter.ingest stores the exact captured record as digest-bound provenance. Tests exercise this persist path and verify that a trusted-integrity connector is rejected.

**Security qualification:** the adapters are read-only. They do not implement send/update/delete operations, webhook subscriptions, provider-side revocation propagation, tombstone/delete synchronization, full incremental-sync cursors or provider commit fencing. The configured OAuth consent scopes and tenant/account IDs are trusted application configuration; this tranche does not independently validate the provider token subject against those IDs or perform OIDC tenant/account binding. ProviderCapture is a host-side integration object and must not be exposed as a model-constructible ingress API.

**Validation:** HTTP behaviour is tested with httpx MockTransport, including OAuth refresh/rotation, scope rejection, Graph lookalike nextLink rejection, Slack API-level denial, Qdrant API-key header, response-size and redirect controls, and persistence through untrusted provenance ingress. No live Gmail/Microsoft/Slack/Qdrant credentials or real customer accounts were exercised by CI.

**Remaining controls:** bind OAuth grants to independently validated workload/user/tenant identity; persist rotated refresh tokens in KMS/HSM-backed secret storage; implement revocation and deletion propagation; add bounded incremental synchronization/webhook processing; add connector audit correlation; and build destination-side commit fences/idempotency before enabling provider writes.

### A-10 — Local SQLite state is not a distributed or tamper-evident security authority

**Severity:** High for multi-host deployments  
**Status:** Partially mitigated for authority/usage/revocation state by a PostgreSQL shared-primary backend; broader evidence and failover guarantees remain open

The repository now includes PostgresAuthorityRegistry, a PostgreSQL-backed implementation of the existing authority-registry contract. It stores authority records, policy epoch, revocations, per-capability usage, task-wide aggregate quota, message replay receipts and local resource-commit receipts/values in one shared PostgreSQL database. HMAC and Ed25519 capability issuers can use this registry through the common API. A test suite creates independent registry clients against the same PostgreSQL service and exercises aggregate quota sharing, cross-client revocation, durable message replay, one-use resource commit receipts and a resource-commit/revocation race.

Every mutating registry operation takes a transaction-scoped SHARE ROW EXCLUSIVE lock across the authority/usage/revocation/receipt/resource tables. This is intentionally conservative: cooperating clients on the same PostgreSQL primary serialize their mutations and observe one serial order. It trades write throughput for an auditable shared consistency boundary.

**Impact after phase-4 change:** workers using the same PostgreSQL primary and this registry implementation no longer create independent per-process SQLite authority/quota namespaces. The tenant/task aggregate quota and revocation/receipt state are shared across those clients.

**Residual impact:** the backend is single-primary. It does not implement multi-primary consensus, read/write split routing, automatic failover safety, stale-backup rollback detection, quorum semantics or tamper-evident audit export. A failover to a replica that has lost acknowledged commits can roll back quota/revocation/receipt state unless the deployment configures and validates an appropriate durability/failover policy. The provenance repository, memory value store and optional Monitor operation ledger remain separate SQLite stores; they are not made distributed by this authority backend. Cross-database/cross-provider atomicity remains unresolved.

**Required control:** require all workers and issuers to use one authenticated PostgreSQL primary; configure TLS, least-privilege service roles, durable WAL and a failover policy that does not promote a replica missing acknowledged commits; add restore/rollback detection and tamper-evident audit export; move provenance/value/operation-ledger state behind compatible shared transactional interfaces before claiming the entire lifecycle state is distributed.


## 3. Budget-accounting model and charge points

PR #14's task quota is a **call-unit ceiling**, not a token, time, monetary, byte, or provider-rate quota. The reviewed code charges task-wide usage for:
- child capability registration/delegation;
- mediated effect execution authorization;
- memory writes and reads;
- metadata disclosure;
- message send (separate from the memory-read authorization of its payload);
- message receive (separate from the recipient memory-read authorization).

A message send/receive can therefore consume more than one task unit because the communication operation and the data-read authorization are separate protected operations. This should remain explicit in API documentation and benchmark accounting.

The quota is only enforced for paths that reach the `HMACCapabilityAuthority` / `SQLiteAuthorityRegistry` APIs. It does not automatically constrain raw database operations, tools that bypass the PACA runtime, or provider-side resource usage. The separate operation ledger/monitor state is not a distributed substitute for `task_usage`.

## 4. Experiments required before effectiveness claims

The current CI/AgentDojo adapter tests and bounded TLC checks are useful regression evidence, but they are not live-agent effectiveness experiments. The previous AgentDojo workflow explicitly skipped live model runs because `OPENAI_API_KEY` was not configured.

Required experiment programme:

1. **Matched baselines:** no guard, framework/tool-filter baseline, PACA #13 only, PACA #13 + #14. Keep model, prompt, tools, permissions, task seeds, injection IDs, budgets and run count matched.
2. **Attack classes:** prompt injection and indirect injection; unauthorized tool invocation; cross-tenant memory retrieval; memory poisoning and summary/compaction laundering; delegated-agent privilege escalation; message spoof/replay; stale/revoked source use; egress exfiltration; tool manifest substitution; direct/alternative execution path.
3. **Concurrency/race tests:** revoke immediately before and after authorization; race sibling agents against the shared quota; race duplicate messages; crash/restart between metadata/value/provider commits; fail over/recover the authority store.
4. **Metrics:** attack success rate, prohibited mediated effects, false-denial rate, task completion, latency, token/API cost, budget exhaustion, replay work amplification, and recovery behavior. Report confidence intervals and per-attack breakdowns.
5. **Independent reproduction:** publish exact commit SHAs, pinned dependencies, model/provider versions, seeds, sanitized traces, scripts and raw result files. Include an independent baseline implementation or reviewer.
6. **No overclaim:** a passing test suite, dry-run, adapter integration test or TLC model check is not a real-agent security-effectiveness result.

## 5. Next engineering gates

1. Close A-01 with resource-side commit authorization/fencing for every consequential provider.
2. Close A-02/A-03/A-04 by hardening the process boundary and auditing every ingress, callback and tool-execution route.
3. Define task identity ownership and shared authority-store topology for A-05.
4. Implement bounded replay/rate controls and explicit receive-delivery semantics for A-06/A-07.
5. Implement asymmetric key management and OIDC/workload identity for A-08.
6. Implement real provider-backed connectors and source/effect authorization for A-09.
7. Replace local-only authoritative state for multi-host deployments and define rollback/tamper controls for A-10.
8. Run matched live-agent experiments and independent baseline comparisons only after the above instrumentation and safety controls are in place.

**Release/claim gate:** Until these gates are satisfied and independently reviewed, PAC++ New should be described as a security research prototype with specific mediated-path controls and documented bypass boundaries—not as production-ready, comprehensive, race-free, independently audited, or universally enforcing agent security.
