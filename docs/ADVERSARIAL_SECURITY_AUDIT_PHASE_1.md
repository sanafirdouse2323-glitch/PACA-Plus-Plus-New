# Adversarial Security Audit — Phase 1

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
**Status:** Open architectural limitation

The runtime checks authority/revocation and then invokes an executor. Revocation can occur after the final local check and before, during or after the remote resource commits the effect. The SQLite transaction that records budget use is not held open across the external operation, and holding it open would not make a remote service participate in the same transaction.

**Impact:** A capability revoked in the check-to-commit interval may still cause a remote effect unless the resource server independently checks authorization at its own commit boundary.

**Required control:** Use resource-side authorization with a monotonic fencing/authorization epoch or single-use operation ID checked atomically at commit. Where the resource cannot enforce this, classify the integration as best-effort preflight authorization and do not claim race-free revocation.

**Evidence to add:** Deterministic concurrency tests that pause immediately after the last PACA validation, revoke the authority, then attempt the resource commit. The expected secure result must be enforced by the resource-side commit check, not merely by another PACA preflight.

### A-02 — Untracked literal arguments depend on trusted ingress

**Severity:** High when agent-controlled code can construct PACA values  
**Status:** Partially mitigated in the protected reference runtime; process trust boundary remains open

The phase-3 trusted-ingress branch changes `TrustedMemoryAdapter.authorize_argument` to reject every protected effect argument without a durable lineage reference. This includes caller-constructed `Arg` values whose `Label` claims trusted integrity, known origins or tenant provenance. Arguments must be captured and persisted through the configured trusted ingress adapter, and their canonical bytes must match the immutable lineage digest before an effect is authorized. The runtime rejects missing lineage before invoking the policy monitor, consuming the protected effect call budget, or entering the executor.

The regression suite covers trusted-looking, default-untrusted and caller-origin-claimed untracked arguments, and verifies that none reaches the monitor or executor. Framework integration tests construct their path arguments through the trusted ingress fixture rather than manually asserting trusted labels.

**Residual trust boundary:** Python code already running with access to the trusted connector, capability-token provider, filesystem and authority registry can still misuse those interfaces. A trusted ingress adapter must obtain source metadata from the provider/framework boundary; it must not merely relabel model-supplied bytes. Process isolation and provider-authenticated source capture remain necessary. Static literals that influence protected effects must also be registered as explicit, digest-bound inputs.

### A-03 — Framework/tool mediation does not cover alternative execution paths

**Severity:** High if the agent shares a process with raw capabilities  
**Status:** Open integration boundary

The middleware and adapters cannot prevent code with access to raw objects from bypassing them. Examples include direct `Tool.invoke`/tool callables, direct LangGraph node callbacks, direct `PostgresSaver` or SQL connection use, direct SQLite value-store/repository access, subprocess/shell execution, arbitrary Python, and separately-created HTTP/filesystem/database clients. The checkpoint wrapper itself documents that its raw delegate and credentials must remain in a trusted process.

**Impact:** Any unmediated path can create effects or disclose state without PACA policy, budget, replay or audit checks.

**Required control:** Run agent code in a process/container boundary that does not expose raw database credentials, provider clients, tool implementations or host filesystem handles. Expose only narrow RPC/tool endpoints that enforce authorization at the resource boundary. Inventory and test every registered tool and callback path; a middleware unit test is not proof that all runtime paths are intercepted.

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

### A-08 — Shared-secret HMAC is not production issuer/verifier separation

**Severity:** High for multi-service production deployments  
**Status:** Open production blocker

The current capability issuer uses HMAC. Any component holding the verification key can mint credentials. The constructor accepts a trusted `identity_verifier` callback but does not implement a production identity provider, OIDC token validation, asymmetric issuer signing, verifier-only public keys, key vault/HSM integration, rotation or revocation distribution.

**Impact:** Compromise of any verifier holding the shared key can become issuer compromise. Key lifecycle and principal/tenant/task binding remain deployment responsibilities.

**Required control:** Introduce an asymmetric signing interface (for example Ed25519 or an approved asymmetric JOSE profile), verifier-only public keys, `kid`-based rotation with overlap/revocation, protected private-key custody, issuer workload identity, and strict OIDC/JWT validation (issuer, audience, signature algorithm, key ID, expiry, not-before, subject and tenant/task claims). Do not treat a decoded JWT or an unverified identity callback as authentication.

### A-09 — Provider integrations are interfaces, not production connectors

**Severity:** High for real-world provider data/effects  
**Status:** Open production blocker

The trusted connector adapter is a reference ingress abstraction. It does not itself authenticate to Gmail, Microsoft Graph, Slack, or a production vector database; fetch provider objects; bind provider tenant/user identity; capture source version/ETag; or enforce authorization at the provider's effect/commit endpoint.

**Impact:** Application callbacks can mislabel, omit or stale-bind source data. Provider-side effects and revocation are not covered unless the provider adapter enforces them.

**Required control:** Build provider-specific connectors with OAuth scopes, tenant binding, object IDs and version/ETag capture, source-side pagination and deletion semantics, webhook/revocation handling, outbound commit authorization, bounded retries, and audit correlation IDs. Use least-privilege credentials and never expose them to agent code.

### A-10 — Local SQLite state is not a distributed or tamper-evident security authority

**Severity:** High for multi-host deployments  
**Status:** Open production blocker

The authority registry, provenance repository, value store and operation ledger are local SQLite components. The PostgreSQL checkpoint provider is not atomically coordinated with the SQLite evidence stores. SQLite transactionality protects cooperating writers to the same local file; it does not provide quorum, multi-host consistency, tamper-evident audit, or cross-database atomicity.

**Impact:** Split-brain workers, restored stale backups, file replacement/rollback, or direct database access can invalidate assumptions about quota, revocation, lineage and audit ordering.

**Required control:** Move authoritative quota/revocation/receipt state to a transactional shared database or dedicated authorization service. Define backup/restore rollback detection, integrity monitoring, least-privilege DB roles, tamper-evident audit export, and consistency/failover tests.

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
