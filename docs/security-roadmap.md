# PAC++ New — implementation status and engineering gates

**Snapshot:** 24 November 2026, after PR #25 was merged to `main` (`0be9aded8c6ec542b00a4af4e727d20e62470cec`).

**Maturity:** research prototype. The repository contains useful reference mechanisms and integrations, but does not mediate every agent lifecycle transition and is not production-ready.

**Project boundary:** this roadmap applies only to `PACA-Plus-Plus-New`. The separate `PACA-Plus-Plus` repository is an enterprise authorization gateway and has a different architecture, codebase and evidence base.

## Current implementation

| Area | Present on `main` | What this does not establish |
|---|---|---|
| Policy monitor | Selected action, target, provenance, sensitivity and tenant checks; strict consequential-monitor profile; digest-bound effect tokens | Complete mediation of every framework state transition, tool call or external side effect |
| Information provenance | Typed lineage records, content digests, parent edges, durable SQLite provenance metadata, explicit derivation and revocation | Truth of source content, automatic capture of all model context or protection from compromised trusted adapters |
| Memory | Separate immutable SQLite value store; mediated reads/writes; pre-fetch authority/tenant/purpose checks and post-fetch digest validation | Distributed memory service, cross-store atomicity or protection from direct raw-database access |
| Authority | HMAC and Ed25519 capability envelopes; task/principal callbacks; policy epoch, delegated revocation, per-capability counters and tenant/task aggregate quota | Built-in OIDC/workload identity, protected key custody, rotation or independent issuer service |
| Shared authority state | Optional PostgreSQL registry for authority, revocation, usage, task quotas, receipts and local resource-commit state on one primary | Multi-primary consensus, rollback-safe failover or distribution of provenance/value/Monitor-ledger state |
| Resource commits | Opt-in local SQLite fence for `write_file` and `mem_write` with one-use permit and transactional quota/authority checks | Mandatory enforcement for all executors or commit authorization at Gmail, Graph, Slack, Qdrant or other remote providers |
| Framework integrations | AgentDojo ToolsExecutor and limited workspace mapper; LangGraph BaseStore; LangChain middleware; PostgreSQL checkpoint wrapper | Prevention of direct calls to raw tools, stores, checkpointers, SQL connections or alternate frameworks |
| Provider ingress | Read-only Gmail, Microsoft Graph mail, Slack history and Qdrant search connectors with bounded HTTPS responses and provenance capture | Live account validation in CI, production OAuth subject/tenant binding, provider writes, deletion sync or remote commit fencing |
| Containment helpers | Optional digest-pinned Docker worker; Linux `openat2` filesystem and DNS/IP-pinned network helpers | Mandatory isolation or end-to-end integration of these primitives into every file, HTTP and tool path |
| Formal models | Bounded authorization and lifecycle TLA+ specifications, checked with TLC | Proof of Python implementation refinement, real database atomicity, host isolation or full lifecycle security |
| Evaluation | Deterministic simulator, adapter tests, protocol fixtures and a limited AgentDojo runner | Independent benchmark results or demonstrated real-world attack prevention |

## Confirmed evidence and its limits

The simulator has 30 author-written deterministic attack scenarios and 11 benign workflows. Its baselines are hand-authored comparators. This is useful for regression tests and ablations, but the scenarios are not an independent benchmark and do not establish production security effectiveness.

The generated simulator output is attached to the latest successful `main`-branch CI run as `paca-benchmark-regenerated`. The live AgentDojo model experiment is credential-dependent and was skipped when `OPENAI_API_KEY` was absent. Adapter tests and dry-run preflight do not count as live-agent evaluation.

The tests deliberately demonstrate bypasses as well as mediated controls. Direct access to raw SQLite values, raw PostgreSQL checkpoint APIs, direct Python tool calls, subprocesses and direct filesystem/network operations can escape the adapters. These are documented in [DIRECT_BYPASS_EVALUATION.md](DIRECT_BYPASS_EVALUATION.md).

## Highest-priority work

Before further security-sensitive changes, a repository administrator must also apply and verify the `main` branch ruleset and release-tag protections described in [REPOSITORY_SECURITY_CONFIGURATION.md](REPOSITORY_SECURITY_CONFIGURATION.md). The guide is configuration guidance, not evidence that protection is currently active.


1. **Define and enforce the trusted execution boundary.** Keep raw provider clients, credentials, database handles, issuer keys and stores out of agent-controlled processes. Inventory every read and write path; block direct bypass with distinct OS identities and adversarial host-level tests.
2. **Make effect authorization unavoidable.** Route every consequential mutation through a resource broker that rechecks current authority, policy epoch, provenance, target, payload and replay/idempotency at the destination commit boundary. The existing local SQLite fence is not a remote-provider solution.
3. **Complete production identity and key management.** Bind issuer requests to an authenticated principal, tenant and orchestrator-owned task. Add OIDC/workload identity, KMS/HSM-backed Ed25519 signing, key rotation, authenticated public-key distribution and emergency revocation.
4. **Define state consistency and recovery.** Decide which state is authoritative, bring provenance/value/operation evidence behind a compatible shared persistence model, and test crash recovery, migrations, restore/rollback and primary failover. Do not call the current PostgreSQL registry a distributed lifecycle store.
5. **Make isolation and approval boundaries explicit.** Require an isolated executor for untrusted tool code, prevent credential access from workers, and integrate a separately authenticated approval service for actions that require human approval.
6. **Prove usefulness independently.** Run matched, reproducible live-agent experiments against maintained baselines (including CaMeL/Progent where applicable), add memory/delegation/revocation/bypass attacks, repeat stochastic runs and report confidence intervals, benign utility, false blocks, latency and cost.
7. **Obtain an independent security review.** Review the threat model, trusted computing base, API contracts, concurrency assumptions, migration/recovery and adversarial test evidence before making stronger claims.

## Claim and release discipline

Until these gates are independently tested, describe the project as a **research prototype with selected mediated-path controls and known bypasses**. Do not describe it as complete lifecycle mediation, universal agent protection, independently audited, production-ready or proven to prevent real-world prompt-injection attacks.

Passing CI means that the checked-in tests and bounded model checks pass for their defined inputs. It is not a security certification.