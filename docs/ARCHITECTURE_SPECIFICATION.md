# PACA++ — Open, Platform-Independent Reference Architecture

**Document:** PACA++ Architecture Specification  
**Version:** 0.2.0-draft  
**Status:** Proposed architecture; not a conformance standard or implementation claim  
**Repository:** PACA-Plus-Plus-New (research repository only)  
**Baseline inspected:** 24 November 2026, main commit a81bbffe3cf081830e7b87bba90f5342a327dfa0

> This document specifies the intended architecture for the research project. It deliberately describes target components and security contracts separately from the code currently implemented. A component appearing in this specification is not evidence that the component already exists or has been independently validated.

## 1. Purpose and scope

PACA++ is intended to be an open, extensible, platform-independent reference architecture for **continuous authorisation and usage control across the lifecycle of LLM agents**.

The architecture addresses five linked lifecycle domains:

1. **Memory:** retrieval, reads, writes, updates, summarisation, compaction, retention and reuse.
2. **Tool use:** tool discovery, selection, argument construction, invocation, result capture and delegation to tools.
3. **Communication:** inbound information, outbound disclosure, inter-agent messages and external destinations.
4. **Planning:** plan creation, plan revision, task decomposition, delegation and selection of proposed actions.
5. **Action execution:** process execution and consequential local or remote effects, including the final resource commit.

The central requirement is continuity: information provenance and authority must remain distinct, traceable and valid as the agent changes state. Every protected transition must be evaluated against current identity, task, purpose, policy, provenance, authority and resource state.

This is a **logical architecture**. It does not require a particular operating system, container runtime, programming language, agent framework, policy engine, database, identity provider or tool protocol.

The specification covers:
- component responsibilities and trust boundaries;
- the relationship between policy decisions, authorisation grants and resource commits;
- platform-neutral interfaces and adapter rules;
- lifecycle security invariants;
- isolation and resource-mediation requirements;
- extension, versioning and conformance principles; and
- a staged path from the current research prototype to the target architecture.

It does not certify the current implementation, claim complete mediation, or define final wire-level schemas. Those require separate versioned interface specifications and conformance evidence.

## 2. Architecture decisions

The following decisions are the foundation of the target design.

| ID | Decision | Consequence |
|---|---|---|
| AD-01 | Keep the PACA++ security model independent of products and vendors. | OPA, MCP, Docker, WASI, LangGraph, PostgreSQL and other technologies are optional adapters or implementations, not architectural dependencies. |
| AD-02 | Separate policy decision from policy enforcement. | A policy engine can advise or evaluate; an enforcement point must independently validate the decision and enforce it at the protected boundary. |
| AD-03 | Separate information provenance from authority lineage. | Trusted information does not create permission; permission does not make information trustworthy. |
| AD-04 | Revalidate at consequential transitions. | A plan-time or tool-call-time decision is not sufficient authority for a later resource commit. |
| AD-05 | Make resource mediation explicit. | Protected resource handles, credentials and raw clients remain outside agent-controlled workers; the broker or destination enforcement point performs the operation. |
| AD-06 | Make execution isolation pluggable but security-profiled. | Platform adapters declare and demonstrate their enforced capabilities. No adapter is trusted merely because it calls itself a sandbox. |
| AD-07 | Fail closed on missing security evidence or unavailable critical controls. | There is no silent fallback from a required isolation, identity, state or commit control to a weaker path. |
| AD-08 | Treat adapters as integrations, not authority roots. | An adapter cannot mint authority, lower policy, erase provenance, bypass revocation or exempt its own effects. |
| AD-09 | Define conformance by demonstrated boundaries. | An in-process guard, isolated worker and destination-side commit fence are different assurance levels. |
| AD-10 | Keep architecture openness separate from software licensing. | Public interfaces and documentation do not by themselves grant commercial-use rights or change the repository licence. |

## 3. Design principles

### 3.1 Open and implementation-neutral

The architecture defines stable responsibilities and contracts, not a mandatory stack. An implementation may use a local policy evaluator, a remote policy service, a container, a virtual machine, a WebAssembly runtime, a native sandbox, an SQL database or another conforming technology.

An optional implementation must not become a hidden requirement of the core. Where a feature is unavailable, the capability must be reported honestly and the relevant security profile must reject operations that require it.

### 3.2 Default deny and complete mediation within declared scope

Every protected operation must cross an enforcement point. An operation that has no registered action mapping, no supported enforcement adapter, unknown security-critical identity, incomplete required provenance, stale policy or unavailable authority state must be denied.

A system may explicitly declare an operation outside its protected scope, but it must not describe that operation as protected by PACA++.

### 3.3 Small and explicit trusted computing base

The trusted computing base (TCB) must be documented for each deployment. At minimum, it includes the components that authenticate principals, verify authority, maintain authoritative security state, evaluate or validate policy, enforce protected operations and commit effects.

Agent models, plans, third-party tools and framework wrappers are not trusted simply because they are integrated.

### 3.4 Least authority and narrow mediation

Workers receive only the capabilities required for a declared task. Protected credentials, database handles, signing keys and unrestricted resource clients are not passed into agent-controlled execution contexts. A broker exposes narrow operations, not a general-purpose proxy that recreates ambient access.

### 3.5 Explicit provenance and authority

Information lineage and authority lineage are linked for evaluation but remain separate records with separate semantics, identifiers, validation and revocation rules.

### 3.6 Evidence before claims

A passing unit test, protocol fixture, bounded model check or mocked provider test proves only the property exercised by that test. Claims about isolation, complete mediation, remote commits, distributed consistency or real-agent effectiveness require corresponding integration, adversarial and operational evidence.

## 4. Logical architecture

PACA++ is organised into logical planes. A deployment may combine components or distribute them across processes and services, provided that the required trust boundaries are preserved.

### 4.1 Policy and administration plane

Responsibilities:
- author and review policy;
- version, approve and publish policy artefacts;
- define action/resource mappings and mandatory controls;
- manage policy epochs and emergency policy changes;
- record who changed policy and why.

Policy administration is a privileged function. Agent-controlled content and tool output must not modify active policy. Policy artefacts used for consequential decisions must have an authenticated origin, an immutable version identifier and a verifiable integrity digest or signature.

### 4.2 Identity and evidence plane

Responsibilities:
- establish the authenticated human, service, agent, workload and provider principals;
- bind each operation to a tenant, task, purpose and execution session;
- validate the receiving principal for delegated work and inter-agent communication;
- supply authenticated evidence about source identity, resource ownership, approval and execution environment.

Identity values supplied by the model or a tool are claims, not proof. A trusted identity adapter must establish the principal from an authenticated source. Unknown, conflicting or unverified identity must not be silently mapped to a privileged default.

### 4.3 Provenance plane

The provenance plane records the origin, integrity, sensitivity, ownership and transformation history of information.

An information object/version record should support:
- stable object and version identifiers;
- source class and authenticated source identity, where available;
- content digest and capture time;
- tenant ownership, including mixed or unknown ownership;
- sensitivity and integrity labels;
- parent object/version references;
- transformation identity and implementation version;
- purpose, expiry, retention and freshness metadata where meaningful;
- revocation or quarantine status.

A content digest proves that the observed bytes match the recorded digest. It does not prove that the content is true, safe or complete.

### 4.4 Authority and usage-control plane

The authority plane issues, verifies, attenuates, tracks and revokes grants.

An authority record should bind:
- authenticated principal and workload identity;
- tenant, task, purpose and audience;
- permitted actions and resource predicates;
- data/provenance constraints and allowed destinations;
- parent grant and delegation chain;
- policy version/epoch;
- issue time, expiry and validity conditions;
- call, rate, cost or aggregate-use budgets;
- approval requirements and evidence;
- revocation and status information.

A grant is not a general bearer permission. It is constrained to an intended subject, task, purpose, operation and resource scope. Delegation must be no broader than the parent grant under a defined partial order over operations, resources, time, purposes, constraints and quotas.

### 4.5 Continuous authorisation core

The PACA++ core defines the security semantics and validates evidence supplied by integrations. Its responsibilities include:
- constructing and validating typed authorisation requests;
- checking principal, tenant, task, purpose and audience binding;
- validating capability authenticity, scope, expiry, delegation and revocation;
- evaluating policy and required obligations;
- checking provenance and information-flow constraints;
- enforcing policy epochs, usage budgets, replay protection and idempotency rules;
- binding approvals and implementation identities to the exact operation;
- issuing narrowly scoped authorisation artefacts; and
- producing structured decision and audit evidence.

The core must not depend on one external policy engine. A policy engine adapter may be used for policy evaluation, but the returned result is not itself an authority credential and cannot override core invariants.

### 4.6 Enforcement and mediation plane

A Policy Enforcement Point (PEP) sits on every protected path. Enforcement points exist at the relevant lifecycle boundaries:
- input and observation;
- memory read and write;
- planning transition and delegation;
- tool invocation and tool-result capture;
- inbound and outbound communication;
- local resource access;
- remote provider access;
- final effect commit.

An enforcement point must validate the current request and relevant evidence, not trust an earlier allow decision without checking its binding and validity.

A **trusted resource broker** is the preferred mediation component for protected resource operations. It performs the resource operation using credentials and handles that are not available to the worker. It independently verifies the caller/session, request binding, current authority, provenance constraints and resource-specific rules. It returns only the result permitted by that operation.

The broker is a logical role. It may be deployed as a separate process, service or other isolated trust domain. The architecture does not prescribe a particular OS process model or IPC technology. The chosen deployment must demonstrate that the worker cannot bypass the broker to reach protected resources.

### 4.7 Integration and adapter plane

Adapters translate external systems into PACA++ contracts. They do not replace those contracts.

| Adapter type | Examples | Required responsibility |
|---|---|---|
| Policy engine | OPA/Rego or another PDP | Evaluate a versioned policy input and return a typed, bounded result; cannot mint or broaden authority. |
| Tool protocol | MCP, HTTP APIs or custom protocols | Authenticate the peer, normalise the operation and arguments, bind the destination and tool identity, and route protected effects through a PEP. |
| Agent framework | LangGraph, LangChain, AutoGen or other frameworks | Map lifecycle events and execution paths into PACA++ requests; disclose uncovered paths and prevent raw clients from bypassing protected mediation. |
| Memory and checkpoint | Local stores, PostgreSQL or other stores | Enforce read-before-disclosure and write/commit controls; preserve object/version lineage and ownership. |
| Identity | OIDC, workload identity, service identity or deployment-specific identity | Establish authenticated principal, tenant, workload and task binding. |
| Resource/provider | Files, databases, mail, collaboration, vector stores and other services | Enforce resource-specific reads/writes and report commit evidence; remote writes need destination-side controls. |
| Execution isolation | Containers, VMs, microVMs, WASI or native sandbox mechanisms | Enforce a declared execution profile and report verifiable capabilities and limitations. |
| Persistence | SQLite, PostgreSQL or another backend | Implement the required transactional, durability, isolation and recovery contract for the selected assurance profile. |
| Audit/telemetry | Local append-only log, SIEM or other sink | Receive structured security events without becoming an authority source. |

The named technologies are examples only. No one of them is required by this architecture.

### 4.8 Audit and assurance plane

Audit events should be generated for decisions, denials, approvals, delegation, revocation, resource access, commit attempts, commits, recovery and adapter failures.

Each event should carry, as applicable:
- event and correlation identifiers;
- authenticated actor and workload;
- tenant, task and purpose;
- action, target and canonical request digest;
- policy version and authority reference;
- provenance references and object versions;
- adapter and implementation identifiers;
- decision, obligations and reason codes;
- commit receipt/idempotency key and outcome;
- timestamps and relevant state versions.

Audit records must avoid secrets and unnecessary content. Audit delivery failure must not turn a denied operation into an allowed operation. Where audit is a mandatory control for a deployment, inability to durably record the required evidence must block the consequential effect.

## 5. Lifecycle authorisation model

The model tracks two linked but distinct histories.

### 5.1 Information provenance graph

The information graph describes where data came from and how it changed. It records source, object/version, digest, parent dependencies, transformation, tenant, sensitivity, integrity and lifecycle status.

Derived content inherits the conservative combination of its inputs. A summary, embedding, memory record, retrieved value or forwarded message must not silently become less sensitive or erase its dependencies. Model-generated summaries, embeddings, compactions and other generated transformations are marked untrusted even when every input was trusted, while retaining maximum sensitivity and all origin/tenant dependencies. A parent edge and content digest prove recorded origin and byte identity, not semantic correctness. The current reference schema has no authenticated transform-validation receipt or model-output trust-promotion path. Unknown or incomplete lineage remains explicitly unknown/incomplete.

Declassification, redaction or trust reclassification is a privileged, explicit transformation. It requires a named authority, policy rule, evidence, new object/version and audit record. Merely transforming text does not declassify it.

### 5.2 Authority lineage graph

The authority graph describes who can perform which operation, on which resource, for which task and purpose, under which policy and constraints.

A child grant must be bound to the parent authority and receiving principal. It must not extend operations, resources, data access, destinations, expiry or budgets. Revocation of an authority must invalidate its descendants according to the defined revocation semantics.

Information provenance cannot create authority. A trusted document, message, model output or memory item cannot issue a capability. Authority cannot upgrade the trust level of information.

### 5.3 Lifecycle transition requirements

| Transition | Minimum required control |
|---|---|
| Input/observation | Establish source identity and provenance before the content is treated as usable context. Unknown sources remain untrusted. |
| Memory retrieval/read | Authorise before releasing bytes; bind the request to tenant, task and purpose; validate object version, digest, lineage and revocation before disclosure. |
| Derivation/summarisation | Preserve all known dependencies and conservative labels; mark incomplete lineage; do not allow the model to self-assert trust. |
| Memory write/compaction | Authorise the writer, target, task, purpose and data lineage; record the new version and transformation; apply retention and revocation rules. |
| Planning | Treat the model's plan as an untrusted proposal. Bind plan dependencies and proposed actions, then independently authorise each selected action. |
| Delegation | Authenticate the receiving agent; attenuate the grant; bind subtask, data scope, purpose, expiry, quotas and revocation ancestry. |
| Inbound communication | Authenticate the sender where possible; preserve sender, channel, message and content provenance separately from authority. |
| Outbound communication | Check recipient, channel, content lineage, sensitivity, purpose, tenant and approval requirements immediately before disclosure. |
| Tool execution | Bind the exact tool implementation, operation, destination and canonical arguments to a current grant and enforcement decision. |
| Resource read | Recheck authority at the resource boundary before releasing the data; record the returned version/digest and provenance. |
| Resource write/effect | Obtain a commit permit bound to the exact request and payload; revalidate current policy/authority and consume the permit atomically with the resource commit where the destination supports it. |
| Revocation/recovery | Invalidate affected grants and descendants; quarantine or re-evaluate affected information; reconcile uncertain operations and preserve recovery evidence. |

## 6. Authorisation is not the same as committing an effect

This separation is mandatory.

### 6.1 Decision

A policy decision is a result for a particular request at a particular time and policy version. It may be allow, deny or require obligations/approval. A decision alone does not authorise arbitrary future operations.

### 6.2 Authorisation grant

After the required identity, provenance, policy and usage checks, the core may issue a scoped grant or effect token. It must bind at least:
- principal/workload, tenant, task and purpose;
- action and canonical request digest;
- target/resource and destination;
- tool/provider implementation identity where applicable;
- policy version/epoch and authority lineage;
- provenance references and relevant object versions;
- approval evidence if required;
- expiry, use limit and unique operation identifier.

Any change to an effect-relevant field invalidates the binding and requires fresh authorisation.

### 6.3 Commit permit and resource-side enforcement

For consequential mutations, the broker or destination enforcement point must verify a short-lived, one-use commit permit immediately before the effect is committed. The permit must bind the exact action, target, canonical payload digest, principal, task, authority, policy epoch, destination identity and idempotency/operation identifier.

The commit path must:
1. authenticate the caller and resource destination;
2. validate the permit and exact request/payload binding;
3. recheck current authority, policy epoch, expiry, revocation and usage limits;
4. enforce resource-specific preconditions and version/ETag checks where available;
5. consume the permit and commit the mutation in one atomic transaction where the resource supports it;
6. return a durable receipt or an explicit uncertain outcome; and
7. record the result for replay protection and recovery.

If the resource cannot provide an atomic conditional commit, the adapter must state the weaker guarantee, implement idempotency/reconciliation where possible, and must not claim atomic resource-side fencing. Exactly-once effect execution must not be claimed merely because a request is retried with the same token.

For reads, the equivalent boundary is before data disclosure: authorise before bytes are released, then bind the returned content/version to its provenance evidence.

## 7. Platform-independent execution isolation

The architecture defines an **Execution Isolation Adapter** contract, not a mandatory operating-system mechanism.

An adapter must declare and, through conformance tests or deployment attestation, demonstrate the capabilities it actually enforces. Relevant capability dimensions include:
- workload identity separation;
- filesystem visibility and read/write restrictions;
- network destination and egress restrictions;
- process creation and child-process restrictions;
- secret and credential isolation;
- protected IPC access;
- privilege/capability reduction;
- immutable or integrity-checked executable identity;
- CPU, memory, process and time limits;
- read-only or restricted runtime filesystems;
- host/resource boundary protection; and
- termination and cleanup guarantees.

A deployment profile names the required capabilities and the evidence used to validate them. The adapter must fail to start, or the broker must deny the affected operation, when a required capability is absent or unverifiable. Silent fallback to ordinary host execution is prohibited.

The worker must not possess raw protected resource credentials, signing keys, authority database handles or unrestricted provider clients. It may request only the narrow operations exposed by its authenticated broker session.

A container, virtual machine, WebAssembly sandbox or native OS sandbox is an implementation option, not a security guarantee by name. The threat model must state which host, kernel, hypervisor, runtime, administrator, hardware and supply-chain components remain trusted. Protection against a compromised host administrator or compromised underlying kernel is not implied.

## 8. Platform-neutral interface contracts

This document defines responsibilities, not final wire schemas. A separate protocol specification must define serialisation, canonicalisation, authentication, error codes, size limits, compatibility and test vectors before independent implementations can claim interoperability.

The first interface family is:

| Contract | Request/response requirements |
|---|---|
| Identity context | Authenticated subject, workload, tenant, task, purpose, audience, session and evidence references; unknown fields cannot grant privilege. |
| Provenance evidence | Object/version identifiers, source identity/class, digest, labels, parents, transformations, freshness and status. |
| Policy evaluation | Canonical request context, policy identifier/version and typed decision with obligations/reason codes; no authority minting. |
| Authorisation grant | Authenticated scoped grant with authority lineage, expiry, quotas, policy epoch and revocation reference. |
| PEP invocation | Exact action, destination, canonical arguments, request digest, tool identity and current evidence; typed allow/deny/obligations. |
| Broker operation | Authenticated worker/session, narrow operation name, resource, canonical payload, permit and idempotency identifier; typed result plus commit/read evidence. |
| Isolation profile | Requested and enforced capability set, implementation identity/digest, configuration identity, limitations and validation evidence. |
| Persistence | Transaction, consistency, uniqueness, durability, concurrency, recovery and migration semantics required by the assurance profile. |
| Audit event | Versioned event schema, correlation identifiers, evidence references, outcome and secret-redaction rules. |

All interfaces must:
- be versioned and documented;
- use canonical representations for signed or digested inputs;
- reject ambiguous, duplicate or malformed security-critical fields;
- use explicit typed error categories;
- apply bounded message sizes, timeouts and resource limits;
- authenticate the peer and protect message integrity;
- distinguish absent, unknown and explicitly empty values;
- be tested with positive, negative, malformed, replay and downgrade cases.

A protocol adapter must not reinterpret a denial as an allow, remove an obligation, widen a resource path or drop security-relevant provenance fields.

## 9. Persistence, concurrency and recovery

Security state is not interchangeable with ordinary application state.

The architecture distinguishes:
- authority and revocation state;
- usage counters, quotas, replay and idempotency records;
- information provenance metadata;
- memory/checkpoint values;
- operation and effect receipts;
- policy versions and adapter identities;
- audit evidence.

A persistence adapter must document which of these records it stores, whether they share a transaction, and its consistency and recovery semantics. A database supporting transactions does not automatically make multiple databases or remote providers atomic.

For a deployment that claims shared authority, concurrent operations must be tested against the same authoritative state. Multi-primary operation, failover, restore and rollback must have explicit rules for preventing stale authority from being resurrected. If rollback or state freshness cannot be established, consequential operations must fail closed.

Crash recovery must distinguish:
- no effect attempted;
- effect not committed;
- effect committed with a durable receipt;
- outcome uncertain because the destination cannot prove either result.

Uncertain outcomes require reconciliation, not blind replay.

## 10. Security invariants

These are normative target properties. They are proposed design requirements, not claims that current code or current models already prove them.

| ID | Invariant |
|---|---|
| INV-01 Default deny | An unrecognised, unsupported, malformed or unmapped protected operation is denied. |
| INV-02 Complete mediation | Every effect declared protected crosses a PEP at every path to the actual resource boundary. |
| INV-03 Identity binding | Every protected request is bound to an authenticated principal/workload, tenant, task, purpose and intended audience. |
| INV-04 Exact request binding | Authority and approval apply only to the exact action, destination, arguments, tool/provider identity and relevant resource/data versions checked. |
| INV-05 Continuous validity | Expiry, policy epoch, revocation, quotas and current authority are rechecked at each consequential transition and at commit. |
| INV-06 Single use and replay safety | A one-use authorisation/commit permit cannot authorise multiple distinct effects; retries use explicit idempotency and reconciliation rules. |
| INV-07 Commit enforcement | Protected mutations are checked at the destination commit boundary; earlier allow decisions do not substitute for commit checks. |
| INV-08 Read-before-disclosure | Protected data is authorised before bytes or model-visible content are released. |
| INV-09 Provenance conservatism | Transformation, summarisation, forwarding, embedding and persistence do not silently upgrade trust, erase sensitivity or remove known lineage. |
| INV-10 Authority attenuation | Delegated authority cannot exceed its parent in any defined scope dimension. |
| INV-11 Revocation closure | Revocation invalidates affected descendant authority and blocks use of stale grants and permits under the defined consistency model. |
| INV-12 Tenant and purpose isolation | Mixed, conflicting or unknown ownership/purpose cannot be silently normalised into a more permissive scope. |
| INV-13 Adapter non-escalation | No adapter, framework, model, tool or policy plugin can grant itself broader authority or bypass mandatory PACA++ checks. |
| INV-14 Fail-closed security dependencies | Loss of required identity, policy, state, provenance, broker or isolation evidence blocks the protected operation. |
| INV-15 Evidence integrity | Decisions, commits, revocations and recovery events are bound to durable, tamper-evident evidence appropriate to the assurance profile. |
| INV-16 No implicit platform guarantee | An isolation profile is accepted only for capabilities demonstrated by the actual deployment; product or OS names alone confer no assurance. |

The repository now includes bounded TLA+ models for authorization, lifecycle state, broker permits/read/commit, finite-set grant attenuation and budgets, and conservative information-flow/declassification. These models cover selected abstractions, not end-to-end mediation of all five lifecycle domains. They do not establish cryptographic broker authentication, general path/URL/provider predicate containment, real database atomicity, crash recovery, platform isolation, adapter conformance or refinement of the Python implementation. Model checking these bounded instances is useful evidence, but does not prove those properties.

## 11. Threat model and trust assumptions

### 11.1 Threats in scope

The architecture must address:
- malicious or compromised user-supplied and externally retrieved content;
- prompt injection and indirect instructions propagated through memory, summaries or messages;
- poisoned or stale memory and checkpoints;
- malicious, buggy or compromised tools and framework integrations;
- unauthorized delegation and cross-agent identity confusion;
- replay, token substitution, argument mutation and time-of-check/time-of-use races;
- stale policy, concurrent revocation and quota races;
- direct access to raw files, databases, network clients, subprocesses or provider APIs;
- adapter substitution, configuration drift and implementation identity changes;
- tenant, task, purpose or destination confusion;
- partial failure, restart, duplicate delivery, crash and uncertain remote outcomes.

### 11.2 Trust assumptions

Each deployment must explicitly identify whether it trusts:
- the host operating system, kernel, hypervisor or managed execution provider;
- the broker process/service and its deployment identity;
- the identity provider and credential issuance path;
- policy administrators and policy signing/distribution;
- cryptographic libraries, key custody and key distribution;
- persistence services and their backup/restore/failover process;
- resource/provider APIs and their commit/idempotency semantics;
- build pipelines, package registries and worker image/artifact supply chains.

A compromised component inside the TCB can invalidate guarantees that depend on it. PACA++ must not claim to protect against a malicious platform administrator, a compromised trusted broker or a compromised underlying isolation substrate unless a separately specified threat model and independent evidence support that claim.

### 11.3 Non-goals

PACA++ does not by itself prove that model-generated content is true, eliminate all harmful model behaviour, guarantee that external sources are accurate, prevent every hardware side channel, or secure a deployment whose trusted identity, host, broker or resource provider is compromised. Content classifiers may support risk reduction but are not substitutes for authority enforcement.

## 12. Adapter trust, discovery and extension rules

An adapter must declare:
- contract and schema versions;
- adapter name, publisher and immutable implementation identity;
- supported operations and resource types;
- security capabilities and unsupported capabilities;
- identity and provenance sources;
- failure and retry semantics;
- persistence/transaction guarantees;
- configuration digest and relevant external dependencies;
- conformance tests and known limitations.

Adapter discovery is not adapter trust. A plugin must be explicitly approved by deployment policy and verified against its identity and version. It cannot register new privileged action types, resource scopes or policy exceptions merely by installing itself.

Optional integrations must be independently replaceable. A conforming implementation may replace OPA, MCP, Docker, WASI, LangGraph, PostgreSQL or any named product without changing the core security semantics.

Breaking changes to a security contract require a major interface version and a documented migration. Additive compatible changes require a minor version. Clarifications and non-semantic corrections may use a patch version. Implementations must reject unsupported major versions and must not silently downgrade to weaker semantics.

## 13. Conformance and assurance profiles

Conformance is a statement about tested scope, not a general security certification.

| Profile | Minimum demonstrated property | Claims not implied |
|---|---|---|
| Profile 0 — Demonstration | Decision logic, schemas and examples operate for the declared demonstration inputs. | No protected execution or resource boundary. |
| Profile 1 — Mediated path | Selected application calls cross tested PEPs; request binding, authority and provenance checks work for those paths. | No protection against direct calls outside the mapped paths. |
| Profile 2 — Isolated worker | A declared worker profile prevents the worker from directly accessing protected credentials/resources under the stated host threat model. | No resource-side commit guarantee unless separately demonstrated. |
| Profile 3 — Brokered resource | Protected reads and mutations are mediated by an authenticated broker or destination PEP, with tested read disclosure and commit-boundary enforcement. | No untested provider, operation, failover or multi-host guarantee. |
| Profile 4 — Lifecycle assurance | All declared memory, tool, communication, planning and execution transitions are covered; bypass, race, revocation, recovery and cross-adapter conformance tests pass for the declared deployment profile. | No universal protection outside the tested scope or against components explicitly trusted by the threat model. |

The profiles are cumulative for the same declared deployment scope: Profile 1 includes Profile 0; Profile 2 includes Profiles 0–1; Profile 3 includes Profiles 0–2; and Profile 4 includes Profiles 0–3. A deployment may implement stronger controls for one resource than another, but it must report per-resource/per-operation coverage rather than assign a higher profile to the entire deployment based on one strong adapter.

A profile claim must identify the exact implementation version, deployment profile, supported actions/resources, excluded paths, test environment, skipped tests and residual trusted components. An optional feature does not satisfy a profile unless it is enabled and verified in the target deployment.

## 14. Required conformance and adversarial testing

The conformance suite must include, at minimum:

1. **Contract tests:** schema validation, canonicalisation, version mismatch, unknown-field handling, malformed requests, bounds and error semantics.
2. **Identity tests:** spoofed principal, tenant/task substitution, stale session, wrong audience, workload impersonation and delegated-recipient mismatch.
3. **Provenance tests:** missing parent, digest mismatch, lineage truncation, mixed tenant, unknown source, summarisation/forwarding, revoked ancestors and attempted trust upgrade.
4. **Authority tests:** overbroad delegation, changed arguments, changed tool digest, expired/revoked grants, policy epoch change, quota races and replay.
5. **Memory tests:** direct-store bypass, pre-read denial, stale version, unauthorized disclosure, post-fetch digest mismatch, compaction and deletion/retention behaviour.
6. **Communication tests:** sender spoofing, recipient substitution, cross-tenant messages, exfiltration destination changes and provenance/authority separation.
7. **Planning tests:** plan mutation, hidden dependency, delegated subtask expansion and re-authorisation after policy or state change.
8. **Execution tests:** direct host/process/framework bypass, worker-to-resource direct access, broker impersonation, unauthorized IPC, secret exposure, image/artifact substitution and resource exhaustion.
9. **Commit tests:** payload mutation, target substitution, concurrent revocation, concurrent quota consumption, duplicate commit, timeout, crash before/after commit and uncertain provider outcomes.
10. **Persistence tests:** concurrent clients, transaction rollback, restart, recovery, backup restore, stale replica, failover and rollback detection where supported.
11. **Adapter tests:** conformance to the same core contract across multiple independent implementations; a mocked adapter test is not a substitute for live boundary tests.
12. **Evaluation tests:** benign-task utility, false blocks, latency, throughput, cost and reproducible attack outcomes, including independent benchmark tasks and stochastic repetitions where appropriate.

Every result must state whether it is a unit test, protocol fixture, integration test, live-provider test, isolated deployment test, model check or independent review. Skipped tests must be reported as skipped, not passed.

## 15. Implementation mapping and current repository boundary

The following mapping relates the target architecture to the research repository as inspected at the baseline commit in the header. It does not certify the components.

The current code is grouped below into six responsibility areas to make the implementation easier to navigate. These are **implementation groupings**, not a collapse of the target architecture's logical planes in Section 4. Policy, identity, information provenance, authority, enforcement and assurance retain distinct security semantics even when modules are presented together.

| Implementation group | Building blocks | Current boundary |
|---|---|---|
| **1. Policy and lifecycle enforcement** | Policy DSL/evaluator modules; `paca/monitor.py`, `runtime.py`, `lifecycle.py`, `agent_runtime.py` | Monitor policy/effect decisions, lifecycle session continuity checks and runtime orchestration are complementary. Only configured requests routed through PACA are covered; internal planning and every framework transition are not intercepted. |
| **2. Authority and usage state** | `paca/authority.py`, `authority_runtime.py`, `authority_registry.py`, `postgres_authority.py`, `ledger.py` | Capability lineage, HMAC/Ed25519 issuance and verification, delegation/revocation, quotas and selected operation-token state. Host-supplied identity remains trusted input. The Monitor operation ledger and authority registry have different state contracts and transaction boundaries. |
| **3. Information provenance and memory** | `paca/provenance.py`, `durable.py`, `memory.py` | Typed information labels and lineage, durable metadata, values, and selected memory/connector/message adapters. Hidden context dependencies are not automatically discovered; direct store access can bypass wrappers. |
| **4. Protected-resource mediation and commits** | `paca/resource_commit.py`, `filesystem_commit.py`, `broker.py`, `broker_write.py`, `unix_broker.py`, `paca/contracts/` | Separate local logical, filesystem, broker read/write and optional Linux IPC paths. They are not a single lifecycle-integrated pipeline, and they do not provide remote-provider commit enforcement or universal host mediation. |
| **5. Execution containment and secure I/O** | `paca/sandbox.py`, `secure_io.py`, `secure_network.py` | Optional Docker command execution and selected filesystem/network controls. Different helpers protect different paths; no mandatory OS-wide isolation is established. |
| **6. Framework and provider adapters** | `paca/integrations/` | Explicit AgentDojo, LangGraph, LangChain, checkpoint and read-only provider ingress paths. Direct calls to raw tools, stores, clients or databases remain possible. |

**Assurance and evaluation tooling is separate from the six runtime groups.** The TLA+ specifications, tests, deterministic simulator, benchmark/load runners, statistics and reports assess selected properties; they are not extra enforcement layers and do not establish implementation refinement or production security.

### 15.1 Why related modules remain separate

The grouping above is intended to remove duplicate *inventory labels*, not to merge components with different security contracts:

- The **Monitor** evaluates policy and verifies effect tokens; the **LifecycleSecurityController** binds selected requests to session/task/purpose/epoch and selected provenance/tool constraints. One does not replace the other.
- The **authority registry** maintains authority, revocation, capability/task quotas and resource receipts. The **Monitor operation ledger** maintains the Monitor's operation/token history, strikes and destination-fan-out state. They are not duplicate databases for the same invariants.
- The **runtime resource fence**, **broker write mediator** and **filesystem commit adapter** have different request, receipt, storage and commit semantics. In particular, the broker write mediator is not automatically part of the runtime lifecycle-controller path.
- The **AF_UNIX transport** provides a separate-process communication and peer-credential boundary for configured mediator calls; it is not a second policy engine or a universal resource broker.
- Compatibility aliases and lazy import shims are retained where they preserve existing public imports. They are not additional implementations and should not be removed without an API-compatibility migration.

Do not merge these modules merely to reduce file count. A source-level consolidation requires demonstrated equivalence of invariants, transaction ordering, failure behaviour, public APIs and regression coverage.

### 15.2 Work required before implementation can claim the target architecture

The next work is specification and evidence driven:

1. Review and stabilise the architecture, threat model, TCB and invariant definitions.
2. Publish versioned interface schemas, canonical encodings, error semantics and test vectors.
3. Define the authority and provenance partial orders precisely, including declassification and revocation semantics.
4. Formalise the broker protocol, peer/session authentication, read disclosure and effect commit state machine.
5. Define persistence consistency, transactional and recovery contracts for each conformance profile.
6. Implement the platform-neutral core contracts and a reference broker boundary.
7. Implement at least two materially different execution-isolation adapters against the same contract before claiming platform independence has been demonstrated.
8. Implement resource adapters that enforce real reads and commits, including provider-specific conditional commit/idempotency where available.
9. Build conformance and adversarial tests that exercise actual process, framework, filesystem, database and provider paths.
10. Obtain independent security review and report uncovered paths and deployment assumptions.

No implementation should be expanded merely to make the code resemble the diagram. The diagram and interfaces must be grounded in testable trust boundaries and explicit failure behaviour.

## 16. Open architecture governance

The architecture is open in the sense that its logical components, security contracts, interface specifications, conformance tests and extension process are intended to be documented and implementable by independent parties.

Governance should provide:
- a public architecture and threat-model change process;
- versioned interface specifications and compatibility rules;
- reference implementations and machine-readable schemas;
- conformance tests and reproducible test vectors;
- an adapter registry or equivalent explicit approval mechanism;
- security advisories, vulnerability reporting and release notes;
- documented deprecation and migration periods;
- a clear distinction between normative requirements and optional examples.

The current LICENSE explicitly states that the PACA++ Academic and Non-Commercial License is source-available, restricts commercial use and is not an OSI-approved open-source licence. This specification does not change that licence, grant commercial rights or settle future licensing. Public architecture openness, source availability and open-source licensing are separate decisions and must be described accurately.

## 17. Decision record

The following are deliberate architectural choices for subsequent implementation work:

- The trusted core is product-neutral. OPA may provide policy evaluation, but it is optional and cannot mint authority.
- MCP may provide a tool transport, but transport interoperability does not itself provide continuous authorisation or resource-side enforcement.
- Docker, WASI, VMs, microVMs and native sandboxes are interchangeable only where their measured capabilities satisfy the same declared execution profile.
- Framework integrations are convenience and mediation adapters; the real security boundary must also constrain direct access to protected resources.
- Storage engines are replaceable only if they meet the selected consistency, uniqueness, durability and recovery contract.
- The five lifecycle domains are first-class. No tool-only or sandbox-only implementation may claim full lifecycle coverage.
- Resource read disclosure and mutation commit are separate enforcement boundaries.
- Cross-platform support is a conformance objective demonstrated by multiple adapters, not a claim inferred from abstract interfaces.

---

**Status reminder:** Version 0.2.0-draft is the proposed target architecture. The current PACA++ research repository remains a security research prototype with selected mediated-path controls, known bypasses and unimplemented architecture components. Passing repository CI does not constitute conformance or security certification.

## 18. Stabilising definitions and security semantics (v0.2.0 review decisions)

This section resolves terms whose ambiguity could otherwise produce incompatible or unsafe implementations.

### 18.1 Normative vocabulary

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT and MAY are normative. MUST/MUST NOT denote requirements for conformance to the relevant profile. SHOULD/SHOULD NOT permit a documented, risk-reviewed exception; they do not permit silent downgrade.

A **principal** is an authenticated human, service, agent or workload identity. A model name, tool-provided user ID, tenant string or caller-supplied subject is only an untrusted claim until an identity authority or authenticated channel establishes it.

A **task** is an orchestrator-created execution scope with an unambiguous owner, tenant and lifecycle. A child task is not inferred from a model plan; it is explicitly created and bound by the trusted orchestrator.

A **policy decision point (PDP)** evaluates policy. A **policy enforcement point (PEP)** blocks or permits the protected operation. A **resource broker** is a PEP that performs a narrow resource operation using protected handles/credentials unavailable to the worker. A PDP response is not a capability and is never sufficient by itself to commit an effect.

An **authorisation grant** permits a bounded operation request under stated conditions. A **commit permit** is a short-lived, one-use artefact for one exact mutation attempt. A **commit receipt** is evidence of the destination's result, not a new grant.

### 18.2 Identity binding at the broker

The broker MUST derive caller identity from an authenticated session or channel whose peer binding it verifies. A worker-supplied principal, tenant, task, UID, role or workload label MUST NOT be accepted as proof of identity. The session must be established by a trusted launcher, identity authority or authenticated workload mechanism; each request is bound to the session, nonce and intended broker audience. The transport adapter can use platform-specific peer authentication, but its externally visible contract remains platform-neutral. Session identifiers are references, not secrets or proof by themselves.

The broker MUST reject an expired session, a mismatched channel binding, replayed request nonce, wrong audience, unrecognised operation, or caller/task/resource combination not authorised by the current grant. A broker adapter must not turn a caller-provided identity field into an authenticated identity.

### 18.3 Delegation attenuation is semantic containment

Represent a grant as a tuple:

    G = (subject, tenant, task, purpose, audience, actions, resources, data_constraints, destinations, not_before, expires_at, budgets, approvals, delegation_rights, parent)

A child grant C is attenuated from parent P only when every dimension is contained by the parent's authority. At minimum:
- tenant and purpose remain equal unless the parent explicitly carries a bounded set of allowed child purposes;
- the receiving subject is named by the parent's delegation authority or separately authenticated approval;
- the child task is created by the trusted orchestrator under the parent task and is within its delegated subtask scope;
- actions and destinations are semantic subsets;
- resource predicates are subsets under the registered predicate semantics, not by textual prefix, glob comparison or string equality alone;
- data constraints are at least as restrictive, including sensitivity, integrity, tenant and lineage conditions;
- child not-before is no earlier than the parent; child expiry is no later than parent expiry;
- operation, byte, cost and rate budgets do not exceed the parent's remaining budget after atomic reservation; and
- approvals/delegation obligations are preserved or strengthened, never removed.

If the predicate implementation cannot prove resource-scope containment, delegation MUST be denied. Wildcard, path, URL, SQL and provider-resource predicates need typed, versioned semantics and dedicated containment tests. A signed string pattern is not proof that one resource scope is a subset of another.

### 18.4 Provenance lattice and declassification

Integrity and confidentiality/sensitivity are separate dimensions. For the current integrity ordering, untrusted is less trusted than trusted; conservative derivation takes the least-trusted input. Sensitivity is ordered from public (0) through restricted (3); conservative derivation takes the maximum input sensitivity and preserves all tenant/source dependencies, including mixed or unknown ownership.

Declassification is not trust promotion. An authorised declassification MAY lower a sensitivity label only through an explicit transformation with a named policy, authorised principal, exact input/output digests, destination/purpose constraints and durable audit evidence. It MUST produce a new object/version. It MUST NOT turn untrusted content into trusted content, erase lineage, or resolve unknown tenant ownership without independent evidence. Redaction and release approval are distinct operations and both must be recorded when both occur.

### 18.5 Revocation closure and freshness

Revocation of grant G MUST make G and every descendant grant unusable for new protected operations. It also invalidates outstanding authorisation/commit permits derived from those grants. Derived information depending on revoked or quarantined sources must be marked affected and denied or re-evaluated under an explicit recovery policy; deleting a source record alone is not proof that derived copies have been removed.

A cache may accelerate status checks but MUST NOT override a newer revocation or policy epoch. A deployment claiming immediate revocation must provide a linearizable status/commit check at the effect boundary. A deployment using bounded-staleness replication must publish its maximum revocation delay and cannot claim immediate revocation; high-consequence operations must fail closed when freshness cannot be established.

### 18.6 Concurrent commit and recovery semantics

The commit boundary is the linearization point for a protected mutation. The system MUST define whether the resource update and one-use permit consumption are in one transaction, a destination-native conditional operation, or a weaker multi-step protocol.

When permit consumption and the resource mutation share an atomic transaction, a concurrent revocation/commit race is serializable: either the commit linearizes first under then-current authority, or revocation linearizes first and the commit is rejected. The system must not claim that revocation cancels an effect that already linearized.

When the destination cannot atomically check the permit or resource version, the adapter must classify the result as weaker/uncertain, use provider idempotency and reconciliation where available, and avoid claiming exactly-once execution or atomic revocation. A timeout after request submission is an **unknown outcome**, not evidence of failure; blind retry is prohibited until reconciliation determines whether the effect occurred.

### 18.7 Trust-boundary and profile reporting

Conformance profiles are cumulative for a declared resource/operation scope, not blanket certifications. Every profile report must enumerate protected resources, operations, entry points, direct-access paths tested, excluded paths, platform adapter and version, TCB, evidence type, skipped tests, residual risks and revocation consistency. A profile achieved for filesystem writes does not imply coverage of filesystem reads, memory, messaging or remote providers.

An adapter's claimed capabilities are untrusted metadata until verified by the deployment's approved conformance evidence or trusted attestation mechanism. An adapter cannot self-certify merely by returning a capability list.

### 18.8 Architecture review exit criteria

Architecture stabilisation is complete only when:
1. the deployment threat model and TCB are explicit;
2. broker caller identity is derived from authenticated session evidence, not worker-supplied claims;
3. resource-scope and delegation containment are defined semantically;
4. provenance declassification cannot promote integrity or erase lineage;
5. revocation consistency and commit linearization are explicit;
6. conformance is cumulative and scoped to named resources/operations; and
7. every normative invariant maps to at least one formal property and one adversarial conformance test, or is clearly marked as not yet modelled/tested.