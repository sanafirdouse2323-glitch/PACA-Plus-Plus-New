# PACA++ New — PhD research prototype dossier

**Project:** PACA-Plus-Plus-New  
**Assessment date:** 28 November 2026  
**Purpose:** technical dossier for PhD research discussions and application evidence  
**Maturity:** research prototype / integration demonstrator; not production-ready  
**Implementation candidate:** PR [#59 — Bind agent communication and delegation to lifecycle sessions](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New/pull/59)  
**Working branch:** `research/lifecycle-session-communication-2026-11-28`  
**Repository boundary:** this dossier applies only to `PACA-Plus-Plus-New`. It does not describe or reuse code or evidence from the separate `PACA-Plus-Plus` enterprise gateway.

## 1. Research proposition

LLM agents do not act through one isolated tool call. User content and retrieved data can influence a plan, persist through memory, be transformed or forwarded to another agent, and eventually affect a protected resource. Authority can also outlive or drift away from the task, tenant, purpose or policy state that originally justified it. A security control applied at only one stage may therefore miss a violation that emerges across several stages.

**Research question**

> Can a unified, composable authorisation and usage-control model preserve information provenance and authority constraints across input and retrieval, memory and context, planning, tool use, inter-agent communication and consequential effect commitment—and does it prevent lifecycle-spanning violations that are missed by the strongest applicable stage-specific controls while preserving benign task completion?

**Falsifiable hypothesis**

> For a declared agent threat model and matched workflows, a connected model of information provenance, authority lineage, usage state and resource-side commit validation will reduce prohibited sink effects compared with the strongest applicable native stage-specific controls, without an unacceptable loss of benign task utility.

This is a hypothesis to evaluate, not a result already established by the repository. A policy denial, a model refusal, a unit test or a larger architecture diagram is not by itself proof that a protected effect was prevented. The primary security oracle is the protected resource's state and trusted commit receipt.

## 2. Research gap and novelty discipline

Existing work already addresses important parts of this problem. PACA++ New must not claim to be the first capability-based agent monitor, the first information-flow control for tool calls, or the first delegated-authority reference monitor.

The repository's research programme identifies the following relevant native comparators:

| Research area | Relevant prior work | Role in the evaluation |
|---|---|---|
| Tool-boundary information flow and privilege policy | CaMeL; Progent | Strong native controls for trusted/untrusted data separation, value-level capabilities and symbolic tool/argument restrictions |
| Multi-agent communication | Multi-CaMeL | Native comparison for preserving instruction/data separation and provenance across delegated agent communication |
| Commit-time authorisation and recovery | AID-Guard | Comparison for request/provider-state revalidation, reservation, ambiguous delivery and retry/recovery under declared provider contracts |
| Stateful delegation/reference monitoring | DelegateGuard; Delegation Without Trust | Close novelty comparators for attenuable authority, broker-mediated effects, delegation, revocation and untrusted agents |
| Benchmark-native tool filtering | AgentDojo native `tool_filter` | Baseline for the subset of AgentDojo workspace tasks supported by the current adapter |

**Defensible research position:** the potential contribution is not any one of these mechanisms in isolation. It is the formally specified and empirically tested composition of information continuity, authority continuity, usage continuity and effect continuity across distinct runtime stages, including the failure and recovery boundary at a protected sink. Whether this provides additional protection over the best layered combination of existing systems remains an open experimental question.

The six-point comparative protocol requires native, version-pinned comparators. A home-written imitation must not be reported as CaMeL, Multi-CaMeL, Progent or AID-Guard. Comparator descriptions in the repository are documentary/source evidence unless a native reproduction has actually been completed.

## 3. Target lifecycle and security model

The research target has six stages:

1. **Input and retrieval:** establish source identity, tenant, version, trust and provenance before content is used.
2. **Memory and context:** preserve source lineage and policy restrictions across write, read, retrieval, compaction and cross-session reuse.
3. **Planning:** treat model-generated plans as proposals, not authorisation credentials; bind the eventual executable request to current policy and context.
4. **Tool execution:** authorise the exact tool, implementation, arguments and authority immediately before execution on a configured PACA path.
5. **Communication and delegation:** bind sender, recipient, task, purpose, information lineage and attenuated authority across agent boundaries.
6. **Effect authorisation and commitment:** revalidate the exact request at the resource boundary and retain evidence of what the destination actually committed.

The continuity model separates four properties:

- **Authority continuity:** principal, tenant, task, purpose, epoch, grant chain and revocation state remain bound.
- **Information continuity:** source identity, labels, lineage and transformation dependencies are preserved without silently upgrading untrusted content.
- **Usage continuity:** quotas, one-use authorisations, replay state and retry identity remain consistent.
- **Effect continuity:** the action, destination, arguments and policy snapshot authorised are the same values that reach the sink.

Information trust is not permission. A valid capability does not make its input trustworthy. A consumed authorisation is not proof of a committed effect.

## 4. Implemented prototype architecture

The README maintains the canonical six-group module inventory. The grouping is for responsibility and navigation; it does not imply six complete, independently deployable layers.

| Responsibility group | Current implementation examples | Boundary that remains |
|---|---|---|
| 1. Policy and lifecycle enforcement | Policy parser/evaluator, Monitor, lifecycle controller and PACA-owned runtime | Only configured paths are checked; hidden planning and direct host/framework calls are not universally intercepted |
| 2. Authority and usage state | HMAC/Ed25519 capability paths, immutable authority lineage, delegation/revocation, SQLite and optional PostgreSQL authority registry | Production workload identity, managed key custody and unified distributed state/recovery are not supplied |
| 3. Information provenance and memory | Typed labels/lineage, durable provenance metadata, separate memory values, trusted adapters and selected framework/message wrappers | Trusted adapters must supply source evidence; raw-store and alternate framework paths can bypass wrappers |
| 4. Protected-resource mediation and commits | Logical resource fences, optional Linux filesystem fence, local broker mediators and optional AF_UNIX transport | Each path is narrow and separately wired; remote-provider destination-side commit fencing is absent |
| 5. Execution containment and secure I/O | Optional digest-pinned Docker worker and selected Linux filesystem/network helpers | Not a mandatory OS sandbox; direct host, subprocess, network and credential bypasses are not universally prevented |
| 6. Framework and provider adapters | AgentDojo, LangChain, LangGraph/checkpoint integrations and read-only provider ingress adapters | Only declared adapter paths are covered; mocked provider CI is not live-account validation |

Formal models, tests, simulators and benchmark runners are assurance/evaluation tools, not additional runtime security groups.

### Lifecycle communication integration in PR #59

The implementation candidate closes a specific continuity gap identified in the Phase A audit. Before this change, `PACAAgentRuntime.execute_effect()` applied active-session checks to selected effect requests, but `delegate()`, `send_message()` and `receive_message()` did not bind those operations to the active lifecycle session.

When a lifecycle controller is configured, the candidate now:

- verifies the parent/sender/recipient capability and immutable authority lineage;
- binds principal, tenant, task, purpose and policy epoch to the active session;
- routes delegation and message operations through an explicit, restricted context-transition API;
- serialises the trusted local adapter operation against `stop()` and `close_session()`;
- supports child tool pins, subject to the issuer's existing parent-pin attenuation checks; and
- records routing metadata and payload digests rather than raw message bytes or token values.

The existing authority issuer remains responsible for delegation attenuation and quota semantics. The message codec remains responsible for message authentication, sender/recipient grants, provenance, revocation and replay receipts. The change does not replace those controls or make direct adapter calls pass through the lifecycle controller.

The lifecycle controller rechecks the active session after its synchronous audit callback, because the configured host audit sink can re-enter the controller under its reentrant lock. This prevents a reentrant callback that stops or replaces the session from being followed by adapter dispatch.

## 5. Connected executable demonstration

The candidate adds deterministic tests in `tests/test_lifecycle_communication.py` for both isolated boundary cases and one connected local-resource trajectory.

**Connected benign control**

1. A host-configured connector captures a versioned source and workspace path.
2. The sender retrieves the source through `TrustedMemoryAdapter`.
3. The experiment records input, retrieval and a candidate-plan digest. The plan is a fixed test fixture, not hidden LLM reasoning.
4. The sender delegates an attenuated capability to a second agent, including a child tool pin already authorised by its parent.
5. The sender seals a lineage-bearing message; a separately session-bound recipient opens it.
6. The recipient calls `PACAAgentRuntime.execute_effect()` using the packaged `Monitor` and the concrete `SQLiteFencedResourceExecutor`.
7. The test checks the actual resource-registry row, version, child authority ID, request digest and commit nonce.

**Connected poisoned-memory control**

The same workflow is repeated with a source explicitly labelled untrusted. The recipient can receive the data, but the consequential write is denied by the lifecycle integrity policy. The test checks that no protected resource row appears and that no successful lifecycle commit authorisation is recorded.

This is a meaningful end-to-end demonstration for the declared local reference path: the benign control reaches the fenced sink, while the poisoned-data control does not. It is not a live LLM experiment, not a general host filesystem experiment, not a remote-provider commit test and not proof that every path in a deployed agent is mediated.

### Reproduction

Use the project environment and run the focused suite:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/test_lifecycle_communication.py -q
```

The full repository CI additionally exercises the Python version matrix, installation profiles, broker UID isolation, AgentDojo adapter, LangGraph integrations, PostgreSQL checkpoint integration, wheel smoke test and repository formatting/lint checks. The branch and commit under review should be used when reproducing the candidate, rather than assuming the change is already on `main`.

## 6. Threat model and trust assumptions

The prototype targets attacks involving untrusted user/retrieved/tool content, indirect prompt injection, memory poisoning, lineage loss, downstream-agent reinterpretation, over-broad delegation, stale/replayed authority, policy changes, revocation races, duplicate requests, direct adapter paths and uncertain effect delivery.

The current local experiments trust the host application/session configuration, source connector identity and labels, issuer/verifier keys, policy engine, configured executor mapping, local SQLite registry, test oracle and protected sink. Those dependencies form part of the trusted computing base.

The following are not established as solved:

- compromised host kernel or trusted issuer;
- arbitrary hidden model-context dependency discovery;
- semantic truth verification or complete semantic reconstruction;
- universal mediation of raw stores, direct framework calls, subprocesses or network paths;
- production OIDC/workload identity and KMS/HSM key custody;
- atomic consistency across all provenance, memory, operation and authority stores;
- general SaaS/provider destination-side conditional commits and ambiguous-delivery recovery;
- all frameworks, providers, agent topologies or operating systems; or
- production availability, side-channel resistance or general denial-of-service protection.

A digest binds supplied bytes and metadata; it does not prove truth. A digest in an audit log is not encryption or a confidentiality mechanism. Audit stores still require access controls and appropriate retention.

## 7. Evidence status on 28 November 2026

Evidence is labelled by what actually ran, not by what the architecture intends.

| Evidence item | Observed status | Permitted conclusion |
|---|---|---|
| Existing targeted unit/regression suites | Present in the repository and exercised by CI | Evidence for the individual declared fixtures and adapter paths only |
| PR #59 Python test matrix | The latest observed run passed Python 3.10, 3.11, 3.12 and 3.13, including the new connected trajectory tests | The branch's tests passed on that run; the subsequent change was a Python-formatting-only whitespace correction and requires a final clean CI rerun |
| Broker UID-isolation, installation-profile security contracts, AgentDojo adapter, wheel smoke, LangGraph integration and PostgreSQL checkpoint jobs | Passed in the same observed CI run | Evidence for the named CI configurations, not universal mediation |
| Repository formatting check | The observed run failed only because of top-level blank-line formatting in the new test file; a follow-up whitespace correction was committed | Do not call the latest revision fully green until a fresh CI run succeeds |
| AgentDojo real-model benchmark | Explicitly skipped because `OPENAI_API_KEY` was not configured | No live model effectiveness result exists |
| Vendor/service comparators | The repository's Phase A matrix marks the external comparators documentary/not-run | No matched vendor/research-comparator result or superiority claim |
| Independent security review | Not completed | No independent certification or external assurance claim |

The working change is a draft PR, not an already merged `main` implementation. Repository branch protection was previously observed as inactive; an administrator still needs to apply and verify the documented ruleset.

## 8. Evaluation programme

The prototype is intended to support a staged, falsifiable study:

- **G0 — Freeze:** threat model, security policy, scenario schema, evidence labels and observable sink.
- **G1 — Strongest baseline:** pin and configure the strongest applicable native controls for each scenario.
- **G2 — Residual gap:** reproduce an in-scope violation after the comparator is configured correctly. Add no generic mechanism unless a real residual requirement is established.
- **G3 — Semantic transformation:** test lineage across rewrite, summarisation, compaction, retrieval and inter-agent transfer; distinguish supplied lineage preservation from model-discovered semantic dependency.
- **G4 — Effect sink:** exercise commit ordering, revocation races, duplicate delivery, timeout-after-commit, restart and recovery with trusted sink receipts.
- **G5 — Model-in-loop:** run a pinned model/provider and retain raw traces; separate unsafe model proposals from enforcement failures.
- **G6 — Confirmatory study:** use disjoint workflow templates, predeclared outcomes, adequate sample size and uncertainty estimates.

Primary outcomes should include prohibited sink effects/attack success, benign task completion, false denials, indeterminate outcomes, latency, token usage and cost. Multiple paraphrases or seeds of one underlying workflow do not constitute independent workflow templates.

The first AgentDojo workspace preflight is documented separately. Its proposed task subset is a harness pilot, not a confirmatory lifecycle study. Live execution requires a protected API credential and an explicitly approved spend cap. Multi-CaMeL, CaMeL, Progent and AID-Guard require their native pinned artifacts and eligible task/contract semantics before reproduction.

## 9. Claims suitable for research discussion

The following claims are supported at the current prototype scope:

- The repository implements several distinct reference controls for policy evaluation, authority lineage, provenance-aware memory, local resource commits, optional containment and framework/provider adapters.
- The lifecycle controller can bind selected PACA runtime effect requests to a session.
- The PR #59 candidate extends that session check to delegation and message send/receive operations routed through the configured runtime.
- The deterministic connected local-resource test demonstrates one benign delegated-message-to-fenced-write path and one poisoned-memory denial path.
- The repository has explicit negative controls and documentation identifying direct paths that remain outside its mediation boundary.

The following claims are **not** supported and must not be used:

- complete lifecycle mediation or a universal agent security boundary;
- proven prevention of prompt injection across arbitrary models and frameworks;
- production-ready identity, key management, isolation or distributed state;
- general remote-provider commit safety;
- superiority over CaMeL, Progent, Multi-CaMeL, AID-Guard, DelegateGuard, Delegation Without Trust or commercial platforms;
- completed live model or vendor benchmarks; or
- independent security certification.

## 10. Primary technical references in this repository

- [README implementation map](../README.md#what-is-implemented)
- [Agent-lifecycle enforcement boundary](AGENT_LIFECYCLE_ENFORCEMENT.md)
- [Phase A lifecycle audit and threat model](LIFECYCLE_PHASE_A_BASELINE_AUDIT.md)
- [Bounded AgentDojo pilot profile](PHASE_A_AGENTDOJO_PILOT_PROFILE.md)
- [Lifecycle communication integration](LIFECYCLE_COMMUNICATION_INTEGRATION.md)
- [Six-point comparative evaluation protocol](SIX_POINT_INDUSTRY_EVALUATION_PROTOCOL.md)
- [Policy-continuity evaluation](POLICY_CONTINUITY_EVALUATION.md)
- [Direct-bypass evaluation](DIRECT_BYPASS_EVALUATION.md)
- [Seven security requirements and evidence status](SEVEN_REQUIREMENTS_STATUS.md)
- [Repository security configuration](REPOSITORY_SECURITY_CONFIGURATION.md)

**Overall assessment:** PACA++ New is a credible research-prototype foundation with a concrete, reproducible local integration path and explicit security boundaries. Its strongest PhD contribution is still a research question to be tested: whether cross-stage continuity and destination-side effect evidence provide additional protection beyond the best existing combination of focused controls. The prototype should be presented as work in progress with measurable engineering evidence, not as a solved or production-secure system.
