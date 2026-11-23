# PACA++ New security roadmap and implementation status

This document is the source of truth for the six remaining security workstreams.
It separates implemented components from deployment and integration work that is
still required. A primitive or passing unit test is not evidence that every real
agent effect is mediated.

## Workstream 1 — Persistent operation ledger and distributed token management

### Implemented in this branch

- paca.ledger.SQLiteOperationLedger stores capability fingerprints and call
  counts, task denial strikes, destination fan-out, operation decisions, and
  single-use token state.
- Monitor(ledger=...) reads persisted state, commits every non-authorising
  decision, and reserves call budget, destination fan-out, operation record and
  token in one BEGIN IMMEDIATE transaction.
- Tokens are random opaque values. The database stores only their SHA-256
  hashes, request digests, status and expiry.
- Token consumption is an atomic state transition from issued to consumed.
  A second consumer, expired token or mismatched request digest is rejected.
- A capability ID is bound to a fingerprint of its authority. Reusing the ID
  with altered grants, tenant, task, lifetime, budgets or tool pins fails closed.
- Ledger unavailability or inconsistent capability state causes the monitor
  to deny rather than fall back to process-local token state.

### Explicit limitation

SQLite provides durable, transactional coordination for multiple processes on
one host using the same local database file. It is **not** a multi-host,
distributed database. A multi-host deployment still needs a server database
backend (for example PostgreSQL), migrations, database-level availability and
backup procedures, clock policy, and integration tests under the deployment's
actual concurrency model.

The current adapter's request-step allocator is still process-local. A durable
ledger does not by itself make the adapter's step counter restart-safe.

Token consumption provides single-use authorisation, not exactly-once external
effects. A crash after token consumption but before an effect can leave the
effect unperformed; a crash after an external effect but before recording its
result can leave the outcome uncertain. Real executors need operation IDs,
idempotency keys where supported, and explicit recovery/reconciliation states.

### Initial use

    from paca.ledger import SQLiteOperationLedger
    from paca.monitor import Monitor

    ledger = SQLiteOperationLedger("/var/lib/paca/operations.sqlite3")
    monitor = Monitor(ledger=ledger)

The database directory and file must be protected by the service operator.
Do not use this example to imply that the demo HTTP API authenticates or issues
trusted capabilities; the reference API still accepts caller-supplied
capability data and is not a production trust boundary.

## Workstream 2 — Secure filesystem and network execution

### Implemented primitives

- paca.secure_io.SecureRoot uses Linux openat2 with
  RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS.
  It returns a descriptor for a regular file resolved beneath a trusted root.
  It fails closed if the required syscall or resolution guarantees are not
  available; it does not fall back to lexical path checks.
- paca.secure_network.resolve_public_endpoints resolves a hostname once and
  rejects the entire DNS answer set if any address is not globally routable.
- connect_pinned connects to the validated numeric socket address rather than
  resolving the hostname again. connect_tls_pinned preserves TLS SNI and
  certificate hostname verification.

### Explicit limitation

These are execution-boundary building blocks, not a complete file or HTTP
executor. Existing tool integrations have not yet been changed to route all file
reads/writes/deletes through SecureRoot, or all outbound requests through
connect_pinned. Redirects must be parsed and revalidated one hop at a time;
the helper does not follow redirects or implement HTTP proxy policy. A caller
must not hand the hostname to another HTTP client that opens a new connection
and resolves it again.

The trusted filesystem root, permissions, mount configuration, service user,
network proxy configuration and TLS policy remain deployment responsibilities.

## Workstream 3 — Authenticated approvals and trusted tool identity

### Existing baseline

The monitor has an approval_verifier callback and request digests bind
approvals to the requested effect. Manifest pinning checks the tool manifest
hash. These mechanisms are useful interfaces, but they do not authenticate a
human approver or attest the implementation actually loaded by a runtime.

### Still required

- A separately authenticated approval service with named approver identity,
  authorisation to approve the relevant action, expiry, one-time decision ID,
  auditable rejection/revocation, and a signature or verifiable credential.
- Approval binding to request digest, principal, tenant, task, action, full
  effect arguments, tool identity and expiry.
- Runtime tool identity evidence tied to the deployed package, image or
  executable artifact (for example a signed deployment attestation), not only
  a self-reported name, version, description or schema.
- Fail-closed handling for missing, invalid, expired, replayed or revoked
  approval/identity evidence.

Do not replace authentication with a boolean callback, model statement, prompt
confirmation or benchmark ground truth.

## Workstream 4 — Complete mediation across the agent lifecycle

The target enforcement boundary must cover every consequential path:

1. Memory: authorise before reading, writing, updating or deleting stored state.
2. Communication: mediate inbound content admission and outbound messages,
   attachments, recipients, channels and transport metadata.
3. Planning and delegation: treat plans as intent, not authority; check each
   delegated capability for attenuation and revalidate every proposed action.
4. Tool invocation and execution: map each operation to explicit effect
   semantics and verify/consume authorisation immediately before the effect.

The current harness has a simulated memory path and the AgentDojo adapter
mediates a limited tool-dispatch boundary. Inbound communication and planning
are not independently mediated by a production runtime. Complete mediation is
not implemented until every route to a consequential effect is inventoried,
instrumented and tested for bypass.

## Workstream 5 — Expanded AgentDojo evaluation with live models

The existing adapter and runner cover a limited read/search subset of the
AgentDojo workspace suite. Mutating workspace operations such as writes,
deletes, sends, sharing and calendar changes are intentionally denied by the
current mapper.

Still required:

- Add reviewed, action-specific mappings for supported write and other
  consequential operations; retain fail-closed behaviour for unsupported tools.
- Select compatible user-task/injection-task pairs from the installed suite
  rather than guessing IDs.
- Run reproducible live-model experiments for identical models, prompts,
  tasks, attacks and settings across no-defence, AgentDojo tool_filter and
  PACA++ conditions.
- Report attack success, benign utility, utility under attack, false blocks,
  execution errors, skipped samples, policy-decision latency and API/model
  configuration separately.
- Retain raw per-task results and logs, record model/version/date, and inspect
  failed samples before publishing aggregate claims.

CI adapter tests and dry runs make no model calls. The live-model workflow is
conditional on the configured provider secret. A skipped live run is not a
benchmark result.

## Workstream 6 — Formal security specification and verification

models/PACAAuth.tla and models/PACAAuth.cfg define a bounded abstract
authorisation protocol. The invariants cover:

- the capability call budget;
- single-use token consumption;
- execution only after token consumption;
- approval bound to the exact request digest and a trusted approver;
- tenant isolation;
- a pinned tool implementation digest; and
- delegation attenuation.

Run the model with:

    bash scripts/run_tlc.sh

The script pins TLA+ tools v1.7.4 and verifies the downloaded JAR's SHA-256
before running TLC. GitHub Actions runs the same bounded model on pull requests.

### Formal-model limitation

The model is an abstract protocol specification, not a proof that the Python
implementation refines the model. It does not yet model filesystem syscalls,
DNS resolution, all PACA policy rules, persistence crashes, database failover,
clock skew, all AgentDojo functions or the full agent lifecycle. Those require
additional models and implementation-to-model refinement arguments.

## Cross-workstream acceptance gates

No workstream should be described as complete until its relevant gate passes:

| Workstream | Minimum acceptance evidence |
|---|---|
| 1. Persistent state | Restart and multi-process tests; concurrent budget/fan-out races; atomic token replay tests; production database backend and recovery tests for multi-host use |
| 2. File/network | Symlink and path-race tests; connection pinning tests; private/mixed DNS answer tests; redirect revalidation; real executor integration and bypass tests |
| 3. Approval/tool identity | Cryptographic verification tests; principal/role/tenant binding; expiry, replay and revocation tests; runtime attestation tests |
| 4. Complete mediation | Inventory of all effect paths; adapter coverage matrix; direct bypass tests for memory, messages, planning, delegation and tools |
| 5. AgentDojo | Reproducible live-model results, matched baselines, raw artifacts, complete denominator/error accounting and reviewed limitations |
| 6. Formal verification | TLC run recorded; invariants reviewed; crash/concurrency/environment assumptions stated; models extended as the implementation evolves |

**Security claim rule:** a unit-tested primitive, local SQLite backend, CI
integration pass, dry run, abstract model or skipped live-model job must not be
presented as a production-ready end-to-end security guarantee.
