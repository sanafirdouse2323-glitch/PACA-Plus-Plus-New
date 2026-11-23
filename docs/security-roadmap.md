# PACA++ New: Agent-lifecycle implementation status and roadmap

This document is subordinate to [the Agent-Lifecycle Security Research Programme](AGENT_LIFECYCLE_SECURITY_RESEARCH.md), which defines the research scope, related work, proposed UCAUM model, threat model, hypotheses, evaluation plan and claim limits.

**Project boundary:** PACA++ New focuses on LLM-agent lifecycle security. The separate PACA++ repository focuses on the enterprise authorization gateway. Do not merge their codebases, roadmaps or completion claims.

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

- Optional `SQLiteOperationLedger` for persisted capability fingerprints, budgets, decision records and single-use token state. It is local-file/multi-process coordination, not a multi-host database or a memory-provenance graph.
- Linux `openat2`-based `SecureRoot` and DNS/IP-pinned socket/TLS primitives. They are not yet wired into every real tool implementation.
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

**Important limits:** the graphs are in-memory and not persistent; legacy `Arg` values may have no lineage references; the model does not authenticate the issuer, sign capabilities, maintain an active policy epoch, revoke descendants, instrument hidden model context or integrate with a real memory backend. Content digests and labels must come from trusted adapters. This tranche specifies and tests semantics; it does not claim end-to-end lineage enforcement.

## Lifecycle coverage gaps

| Lifecycle surface | Current evidence | Work still required |
|---|---|---|
| Input / observation | Simulated receive/ingest; AgentDojo tool outputs | Trusted source identity, typed input channels, complete connector coverage |
| Provenance / derivation | Typed in-memory object/version DAG, parent edges, content digests, conservative label propagation and lineage-bound request digests | Trusted connector integration, automatic transformation hooks, durable serialization, context/compaction coverage and real memory-store lineage |
| Memory | Simulated guarded read/write; memory labels | Real memory-store adapter, all write channels, retrieval lineage, versioning, quarantine, revocation and delayed-trigger tests |
| Planning / decision | Action requests are checked by monitor | Instrumented plan/decision transitions; plans treated as proposals; revalidation when state changes |
| Delegation | Capability parent/attenuation checks plus typed authority DAG and immutable scope/epoch snapshot | Authenticated issuer/recipient, signed grant chain, precise policy-epoch semantics, active revocation, multi-hop runtime propagation and cross-agent tests |
| Communication | Agent message is an untrusted simulator source | Authenticated typed envelopes, provenance preservation, sender/recipient/channel checks, boundary-laundering tests |
| Tool/effect | AgentDojo pre-dispatch adapter for supported read/search calls | Complete action/effect contracts, real executor integration, resource-side checks and bypass tests |
| Execution containment | Linux `openat2` and DNS/IP-pinning helper tests; a generic toy sandbox comparator | Pinned OpenShell / OpenAI environment integrations, full process/network mediation, redirect revalidation, credential brokering, supervisor-failure and host-escape tests |
| Revocation / recovery | Expiry, budgets and token use are partially represented | Explicit revocation epochs, descendant invalidation, stale memory handling, quarantine and replayable recovery |
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

PACA++ New remains a **research prototype for provenance-aware, capability-based authorization across selected LLM-agent lifecycle boundaries**. It is not a complete lifecycle security product, production agent runtime, enterprise gateway or independently validated security guarantee.
