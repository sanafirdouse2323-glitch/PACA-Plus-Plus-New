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

## Lifecycle coverage gaps

| Lifecycle surface | Current evidence | Work still required |
|---|---|---|
| Input / observation | Simulated receive/ingest; AgentDojo tool outputs | Trusted source identity, typed input channels, complete connector coverage |
| Provenance / derivation | Explicit integrity, sensitivity, tenant and origin labels; explicit joins | Stable lineage graph, transformations, unknown dependencies, provenance across framework state and compaction |
| Memory | Simulated guarded read/write; memory labels | Real memory-store adapter, all write channels, retrieval lineage, versioning, quarantine, revocation and delayed-trigger tests |
| Planning / decision | Action requests are checked by monitor | Instrumented plan/decision transitions; plans treated as proposals; revalidation when state changes |
| Delegation | Capability parent and attenuation checks in selected paths | Formal partial order, authenticated recipient, multi-hop chain, revocation propagation and cross-agent tests |
| Communication | Agent message is an untrusted simulator source | Authenticated typed envelopes, provenance preservation, sender/recipient/channel checks, boundary-laundering tests |
| Tool/effect | AgentDojo pre-dispatch adapter for supported read/search calls | Complete action/effect contracts, real executor integration, resource-side checks and bypass tests |
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
8. **Evaluate against external baselines.** Reproduce compatible public benchmarks first, then add delayed-activation and lifecycle-composition cases. Keep model calls, raw results and error denominators explicit.

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
