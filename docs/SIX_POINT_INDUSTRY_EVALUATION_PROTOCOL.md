# Six-point comparative security evaluation protocol

**Status:** execution protocol and baseline evidence register; not a completed comparative experiment.  
**Repository:** `PACA-Plus-Plus-New` only.  
**Baseline commit:** `ef449fb9813f4070de07143981a2d5ca22cf7ded` on `main`, inspected 26 November 2026.  
**Purpose:** turn the six proposed research priorities into a falsifiable, reproducible engineering and evaluation programme.  
**Claim boundary:** no vendor product is represented as tested until its real service/runtime is configured, version-pinned, exercised, and its raw outputs are retained.

## 1. Executive position

The six workstreams are feasible as a staged programme. They are not all executable in the same environment or with the same evidence method.

1. A source-grounded capability audit can be completed from official documentation and public artefacts now. A live vendor comparison additionally requires the relevant cloud projects, accounts, subscriptions, tenant configuration, supported regions, and access permissions.
2. A residual gap can be claimed only after the strongest applicable controls have been configured for the exact policy and threat assumptions and a violation is reproduced. A documentary gap is not proof that a product lacks the capability.
3. Semantic transformation tests can be built in the local harness now. Model-mediated reconstruction tests require a pinned model/runtime and a separate model-in-the-loop run.
4. Local protected sinks with transactional/fencing behaviour can be tested in the repository. A real external effect guarantee requires a provider/sink contract that exposes an enforceable commit or conditional-write boundary.
5. The repository already has a bounded AgentDojo runner. The latest main CI run on 26 November 2026 completed the adapter integration but skipped the credential-gated live model benchmark; a successful CI run must not be reported as a live agent experiment.
6. Reproducible security and utility metrics can be added to the harness. Statistical claims require independent workflow templates, frozen outcome rules, raw traces, and a sample-size/power analysis. Repeats of one template are not independent scenarios.

The project must remain a research prototype until host-level mediation, trusted identity and key services, distributed-state guarantees, provider-side effect enforcement, deployment resilience, independent evaluation, and external review have been demonstrated. This protocol does not change that maturity status.

## 2. Current repository baseline and known evidence

At the time of this protocol:

- `main` points to `ef449fb9813f4070de07143981a2d5ca22cf7ded`.
- The main-branch CI run `45791461955` completed successfully. The Python matrix (3.10–3.13), lint, wheel smoke test, AgentDojo adapter integration, LangGraph integration, PostgreSQL checkpoint integration, and Docker build passed.
- The separate `agentdojo-real-benchmark` job was **skipped**, not passed, because the required model credential was not available to that run.
- The repository still reports `main` as unprotected. A repository administrator must apply and verify the ruleset described in [REPOSITORY_SECURITY_CONFIGURATION.md](REPOSITORY_SECURITY_CONFIGURATION.md).
- The deterministic benchmark currently compares PACA against hand-authored toy models: no guard, a prompt filter, a role allow-list, and a simplified sandbox-style policy. These models are useful regression baselines, but they are not AWS, NVIDIA, Microsoft, Google, or research artefact implementations.
- The deterministic corpus currently contains 30 author-written attack scenarios and 11 benign workflows. They are not an independent benchmark corpus.
- The AgentDojo adapter is restricted to the explicitly supported workspace task/tool subset. It must not be described as full AgentDojo coverage.
- The current local resource-commit code covers a logical resource store and an optional Linux/local-filesystem write path. It does not implement a remote provider's atomic commit, general remote read mediation, or universal host-level mediation.
- The latest repository documentation already discloses these boundaries in [README.md](../README.md), [security-roadmap.md](security-roadmap.md), and [CONTAINMENT_EVALUATION.md](CONTAINMENT_EVALUATION.md). This protocol preserves those statements.

Evidence labels used in all output:

| Label | Meaning | Permitted conclusion |
|---|---|---|
| D | Documentary audit of official documentation, paper, or source description | What the source documents or claims; not runtime behaviour |
| I | Source/code inspection of a pinned artefact | What the inspected code appears to implement; not a passed execution test |
| R | Reproduction or conformance run against a pinned artefact | Behaviour observed for that exact artefact/configuration and test |
| V | Live vendor/service run in a configured account or tenant | Behaviour observed in that configured vendor deployment and version |
| S | Project-owned simulator or test double | Behaviour of the project-owned model only |
| F | Formal result from a declared model and finite bounds | Property checked within that model/bound; not proof of implementation refinement |

Never convert D, I, S, or F evidence into a V claim. Keep each result attached to its exact source version, commit, policy, configuration, adapter, threat model, sink contract, and raw trace.

## 3. Workstream 1 — strongest applicable baseline

### 3.1 Products and mechanisms to assess

These products do not provide interchangeable controls. Do not rank them on one generic "security score". First map each one to the precise boundary it controls, then test the strongest feasible applicable profile.

| System | Documented security role | Best-fit test dimensions | Important qualification |
|---|---|---|---|
| Amazon Bedrock AgentCore Policy — Temporal Policies | Gateway policy enforcement using session history, prior successful actions, approvals, sequence conditions and cumulative count/sum usage | Tool-call sequences, approval-before-action, target/argument matching, session usage and temporal policy decisions | Session IDs are customer-managed. Authenticated same-account/same-Region AgentCore hops can propagate the workload identity token; non-AgentCore hops require explicit propagation logic. With `authorizerType=NONE`, callers sharing a session ID share one event stream and temporal enforcement is advisory, not per-caller isolation. A same-action temporal condition can include the current request; successful actions are recorded as `response`, denied actions as `error`. Published quotas include 20 temporal policies per engine, 3 temporal operators per policy and a 24-hour lookback. Temporal Policies are unavailable in Asia Pacific (Hyderabad) but listed for Mumbai in the reviewed regional table. Recheck quotas and regional availability at test time. |
| NVIDIA OpenShell | Agent sandbox and runtime containment with kernel-enforced filesystem, syscall and network controls; process identity, credential mediation and policy-change verification | Filesystem/process/network bypass, credential exposure, DNS/TCP mediation, policy tampering and supervisor failure/recovery | This is a strong OS/runtime containment layer, not a drop-in workflow provenance or business-authorization PDP. Current architecture documentation describes a separate trusted supervisor, Landlock/seccomp on Linux, credential insertion only for approved destinations and a fail-closed workload freeze if the supervisor channel drops (termination if recovery misses its deadline). Pin the exact release and host backend. BlueField/DPU-specific claims require that hardware path. |
| Microsoft Entra Agent ID | Agent identities and blueprints, authentication, OAuth-based access, delegated/application permissions, lifecycle governance and resource-side access policy | Principal authenticity, delegated identity, token audience/subject, lifecycle and access to a protected API | Agent ID identity creation is available to Entra customers, but Conditional Access and extended security/governance capabilities have distinct Agent 365/Entra licensing requirements. Agent ID lifecycle policies are preview and have no SLA; they are not recommended for production workloads. The target resource still validates tokens and makes its own access decision. Identity is not by itself memory provenance, sandboxing or atomic provider-effect commit. |
| Google Cloud Agent Gateway | Network ingress/egress policy enforcement for client-to-agent and agent-to-anywhere paths; Agent Identity/Registry, IAM, Model Armor and semantic governance | Tool/egress requests, MCP/A2A routing, workload identity, destination restrictions, content inspection and network telemetry | Only traffic actually routed through the Gateway is covered. Google documents Gemini Enterprise Agent Platform and GKE support, with Cloud Run and external Kubernetes in Limited Preview. Both the current Agent Gateway overview and standalone token-management page say that token-management policies and extension bindings are coming soon; exclude those features from a present-day baseline. Confirm exact project, region and deployment eligibility before a live test. Do not infer visibility into unmediated internal memory or hidden planning. |
| Palo Alto Prisma AIRS (context-only; excluded from primary count) | Broader AI application/runtime protection and threat controls | Runtime threat detection, prompt injection, sensitive-data and model/application security | Include only as documentary context or in a separate non-pooled live stratum where specific product features and test interfaces are available. It is not part of the primary 16-system comparator register or B2/B3 quantitative baseline unless a specific authorization policy and observable effect path are independently defined. |
| MCP runtime-policy PEP (Wang, Zhu and Li, 2026) | MCP tool-call PEP with source-integrity and data-sensitivity labels, cross-step propagation and hash-chained decision records | MCP call mediation, data-flow labels, cross-step provenance and attack/false-negative reproduction | The paper was published in June 2026, while the linked repository README still contains an earlier “manuscript under preparation” note. Treat that as a documentation-version discrepancy. The matrix remains D until a commit-pinned source audit and smoke test are completed; do not assume README-described metrics are independently reproduced here. |
| Progent | Symbolic constraints over tool names and typed arguments, including privilege restrictions and policy generation/update | Tool selection, argument checks, privilege attenuation/expansion and policy updates | Do not generalize tool-call results to memory, communication or terminal effects unless the exact artefact and interfaces demonstrate those paths. |
| CaMeL | Separates trusted control flow from untrusted environment data and enforces value-level capabilities at tool boundaries | Trusted/untrusted data separation, value provenance, tool authorization and data exfiltration | The original paper assumes a trusted user query and has explicit threat boundaries. Its guarantees do not automatically compose across independently implemented agents. Preserve its interpreter, capability model and threat assumptions in any reproduction. |
| Multi-CaMeL | Adds an agent-to-agent protocol that separates trusted natural-language instructions from untrusted data channels and carries provenance across agent boundaries | Cross-agent communication, downstream trust reinterpretation and multi-agent prompt injection | The paper specifically reports that individual-agent CaMeL guarantees do not compose in a hierarchical multi-agent setting. Its findings and utility tradeoffs are tied to its evaluated MultiAgentDojo/AssetOpsBench setups; this is not a generic provider-commit guarantee. |
| Sapien | Stateful contextual policies for tool-call sequences, using regular expressions with stateful predicates, deferred policy generation and scoped semantic checks | Long-horizon tool use, sequence authorization, contextual predicates and policy generation | Published AgentDojo/Toolathlon results are author-reported for the paper's exact tasks and configuration. They are not a PACA reproduction and do not establish general memory provenance or provider-side commit safety. |
| FORGE — Formal Policy Enforcement for Agentic Systems | Datalog policies evaluated over event graphs; checks a proposed action against current state and prior events at the action decision point | Event history, stateful tool authorization and history-dependent policy enforcement | Use the current paper title/version; earlier versions may use a different name. Formal properties are bounded by the declared event model, event completeness and monitor placement. Missing or bypassed events must be tested explicitly. |
| VIGIL | Runtime enforcement of behavioural specifications over agent-tool traces, including temporal dependencies, argument constraints and cross-call value-flow conditions | Skill/runtime policy, temporal events, argument relationships and value-flow | The paper's symbolic checking is over finite traces and a declared event model. Its model-run recall/false-positive results are paper-reported, not comparable without matched policies, tasks and independent reproduction. |
| AgentSpec | Domain-specific language for configurable runtime constraints using triggers, predicates and enforcement mechanisms | Runtime policy specification, domain-specific safety constraints and rule enforcement | The ICSE 2026 work spans distinct domains (including code agents, embodied agents and autonomous driving). Select one native domain and adapter for comparison; do not pool different action semantics or transfer results across domains. |
| DelegateGuard | Purpose-bound, attenuable capabilities over purpose, labels, operations, sinks and delegation depth; an external reference monitor mediates data-moving actions and cascades revocation | Delegated authority, model-independent execution enforcement, sink checks, information labels, revocation, intra-tool flows and multi-agent tasks | A very close novelty comparator. Its paper reports four baselines, 517,401 Enron emails, two open models proposing attacker-goal actions on 42/45 and 44/45 injected traces with all such proposals blocked, and a 90-run multi-turn leakage reduction from 0.844 to 0.20 with full task completion. It also explicitly proves a capability/content-governance boundary: a content- and quantity-blind capability monitor cannot prevent leakage to an already-authorised externally observable sink; the paper says intent inference and all side channels are not solved. These are author-reported paper results, not reproduced here. |
| Delegation Without Trust | Authorization-broker design under an untrusted-model threat model, targeting confused deputy, token theft/replay, prompt-injection privilege escalation and compromised sub-agents | Broker enforcement, identity/authority confinement, token replay, sub-agent confinement and framework threat coverage | The paper reports 11 resisted design attacks, 0/200,000 accepted forged tokens, mean reachable actions of 1.5 versus 8,100 under bearer delegation across 2,000 synthetic scenarios, and about 2.6 μs per decision. The paper's threat model trusts the broker/PEPs and authenticated workload identities; the described broker is a separate reference implementation rather than an end-to-end integration into its evaluated frameworks or a live-model trial. These are author-reported results, not reproduced here. |
| CapLease | Durable authorization state across Issue–Prepare–Commit, addressing semantic replay through freshly reissued token identifiers | Authorization consumption, cumulative usage, concurrency, retry and crash recovery | The paper distinguishes token-identifier replay from reissuing a fresh token for the same underlying authority. Preventing duplicate external effects additionally requires an idempotent sink/effect identity; issuer state alone is not a general provider transaction. |
| AID-Guard | Stateful authorization-to-effect closure with exact-request/provider-state revalidation at commit, reservation retention while delivery is ambiguous, and successor release only after terminal or certified-no-effect evidence plus a delivery fence | Commit-time authorization, ambiguous delivery, reservations, provider retries, concurrency and recovery | Its at-most-one-effect claims are conditional on supported provider contracts and a declared effect-path inventory. The paper's Python/SQLite prototype and Stripe/Resend/loopback-MCP trials are paper-reported evidence, not independent validation or a guarantee for arbitrary providers. |

### 3.2 Documentary source register (reviewed 26 November 2026)

- AWS Temporal Policies, regional support and policy limits: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html
- AWS policy sessions, WAT propagation and unauthenticated gateway caveats: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-session-based-temporal.html
- AWS quotas: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
- NVIDIA OpenShell current architecture: https://docs.nvidia.com/openshell/about/architecture
- NVIDIA OpenShell versioned architecture example: https://docs.nvidia.com/openshell/v0.1.7/about/architecture
- NVIDIA OpenShell repository and release record: https://github.com/ai-openshell/openshell
- Microsoft Entra Agent ID: https://learn.microsoft.com/en-us/entra/agent-id/
- Microsoft Agent ID and Agent 365 licensing: https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id
- Microsoft Conditional Access for agents and licensing: https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id
- Microsoft Agent ID lifecycle policies (preview): https://learn.microsoft.com/entra/id-governance/agent-lifecycle-policies
- Google Agent Gateway overview and governed access paths: https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview
- Google Cloud Run Limited Preview: https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/cloud-run-overview
- Google token management policy overview: https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/token-management-overview
- Prisma AIRS AI Runtime Security: https://www.paloaltonetworks.com/resources/datasheets/ai-runtime-security
- MCP PEP published paper: https://doi.org/10.3390/electronics15132829
- MCP PEP artefact (pin commit and reconcile README publication-status text before reproduction): https://github.com/wilesanGH/mcp-pep-agent-security
- Progent: https://arxiv.org/abs/2504.11703
- CaMeL: https://arxiv.org/abs/2503.18813
- Multi-CaMeL: https://arxiv.org/abs/2610.05640
- Sapien: https://arxiv.org/abs/2610.00797
- FORGE — Formal Policy Enforcement for Agentic Systems: https://arxiv.org/abs/2602.16708
- VIGIL: https://arxiv.org/abs/2606.26524
- AgentSpec (ICSE 2026): https://doi.org/10.1145/3744916.3764546
- CapLease: https://arxiv.org/abs/2608.01710
- AID-Guard: https://arxiv.org/abs/2608.21159
- DelegateGuard: https://arxiv.org/abs/2610.16005
- Delegation Without Trust: https://arxiv.org/abs/2609.00267

The source register is an initial audit, not a completed systematic review. Record access date, release/version, relevant page/section, and evidence excerpts in the machine-readable result for every eventual claim. Recheck product availability and feature maturity immediately before live testing; current public documentation can change.

### 3.3 Baseline configurations

Use the same policy intent, scenario opportunity, principal/tenant mapping, and observable outcome wherever the native interfaces permit. Preserve native semantics; never silently rewrite a vendor control into a PACA policy and label it the vendor.

| Profile | Configuration | Purpose |
|---|---|---|
| B0 | No enforcement | Negative control; confirms the scenario can cause the prohibited effect |
| B1 | Existing project toy baselines (prompt filter, RBAC, sandbox simulation) | Regression/control sanity only; not industry evidence |
| B2-AWS | AgentCore Gateway + Temporal Policies + authenticated caller/session identity | Native AWS temporal-policy profile |
| B2-NVIDIA | OpenShell sandbox + strongest applicable filesystem/process/network policy + credential provider | Native runtime-containment profile |
| B2-Entra | Entra Agent ID + least-privilege token/consent configuration + protected test API | Native identity/authorization profile |
| B2-Google | Agent Gateway + Agent Identity + Agent Registry + strongest applicable IAM/semantic/content policies | Native Google gateway profile |
| B2-Research | Each eligible research artefact in its pinned native configuration; give DelegateGuard and Delegation Without Trust separate native baseline runs where the artefacts and dependencies permit | Research prior-art profile; compare their native attacker, policy, workload and observable-sink semantics before any PACA mapping |
| B3-Layered | Strongest technically compatible combination of identity, gateway/temporal enforcement, runtime isolation and provenance/authorization controls; include a research broker/capability PEP such as DelegateGuard or Delegation Without Trust only where actual interoperation is demonstrated | Best-available layered baseline; native combinations must be smoke-tested, not assumed |
| P | PACA configuration under evaluation | Candidate treatment, not presumed better |

A system is eligible for a paired quantitative comparison only if the scenario reaches the system's native enforcement path without bypassing or changing the system's semantics and the final effect can be observed. If the systems cannot accept the same fixed proposal, compare their native workflows in a separate stratum; do not pool those results with B/P estimates.

The B3 profile is assembled from controls that can actually interoperate under the declared deployment assumptions. This includes testing the strongest feasible research capability/broker mechanism alongside identity, gateway and runtime containment, not merely layering vendor products. Do not assume DelegateGuard or another broker can be dropped into an arbitrary host, that Entra identity tokens automatically become Google SPIFFE identities, that AWS WAT context survives arbitrary gateways, or that multiple network gateways can be stacked without changing routing/identity behaviour. Prove each integration in a smoke test and record the translation boundary. A theoretical product combination is not an executed baseline.

### 3.4 Baseline selection and fairness rules

1. Freeze the policy corpus and the protected sink contract before selecting the baseline.
2. For every product, identify identity source, policy semantics, state/history scope, event visibility, mediation point, fail-open/fail-closed behaviour, administrator/configuration assumptions, and protected effect boundary.
3. Use the strongest documented control that can express the selected policy. If a capability is unavailable in the test edition/region/tenant, record that as an availability limitation, not a security failure.
4. Use identical adversarial and benign opportunities where supported. Do not handicap a vendor baseline by withholding a supported configuration.
5. Preserve the product's own decision logs and native outcome; separately capture the common harness trace.
6. Keep unavailable systems as D/I evidence and mark the matched comparison unavailable. Do not replace a vendor with a hand-coded imitation and call it a vendor run.
7. Include a configuration appendix: release/commit, region, service tier, policy text, identity setup, tool schemas, gateway routes, sandbox configuration, test sink, and all exclusions.

## 4. Workstream 2 — demonstrate a genuine residual gap

A residual gap is accepted only when all of these conditions are satisfied:

- The requirement is declared in the frozen policy corpus and threat model before results are inspected.
- It has an explicit principal, tenant, task, data/authority origin, operation, recipient/target, policy version, relevant event sequence, and externally observable prohibited effect.
- The selected baseline is the strongest applicable configuration, including appropriate combinations where feasible.
- All required enforcement points are in the tested path; an unmediated path is recorded as an architecture coverage limit rather than a defect in a product that does not claim to mediate it.
- The violation is reproduced against a pinned R/V artefact or an exact project-owned implementation of declared semantics. D-only evidence supports only the phrase "not demonstrated in the reviewed documentation".
- The run is repeatable under frozen reset procedures and has raw decision traces plus sink-side evidence.
- A minimum established remedy (policy strengthening, correct identity propagation, complete mediation, provenance propagation, transaction/reservation, idempotency or fencing where applicable) has been tried first.
- A negative result is reported as "no violation observed in these tests", never as a universal proof of safety.

The residual test record must contain: requirement ID; initial conditions; trust assumptions; exact scenario template; comparator configuration; expected decision; actual decision; enforcement point; sink state before/after; evidence source; exact replay command; trace hashes; and explanation of why the violation is within the system's declared scope.

If all strongest baselines pass, Gate 2 must reject the new control for that requirement. The project can still contribute a comparative finding and a bounded formal model; it must not manufacture a gap to justify PACA.

## 5. Workstream 3 — provenance across semantic transformations

### 5.1 Threat and test families

Use source-labelled synthetic data with a non-sensitive unique ground-truth marker plus semantically meaningful restricted facts. Do not equate a text substring detector with semantic provenance.

Minimum fixture families:

- Direct copy and exact extraction.
- Paraphrase that preserves the restricted fact but changes wording and syntax.
- Summarisation at short, medium and multi-document levels.
- Entity/value extraction, table-to-prose conversion and structured JSON generation.
- Translation, reordering, chunking, recombination and selective omission.
- Memory write, compression/compaction, retrieval in a later turn, and reuse in a derived artifact.
- Agent-to-agent forwarding, delegation, message quoting and tool-result handoff.
- Reconstruction from multiple individually non-sensitive fragments whose combination reveals the restricted fact.
- Benign transformations and benign unrelated outputs, to measure false denials.
- Model-in-the-loop transformation variants with model, prompt, sampling settings and version pinned.

### 5.2 Oracle and expected behaviour

The primary oracle is an explicit lineage relation: every derived artifact records the source artifacts and the transformation operation, even when its text is not lexically similar. The policy decision is made from the inherited restriction and recipient/target authorization, not from a search for a secret string alone.

**Integrity-semantics correction implemented on this branch:** `Label.as_model_output()` now downgrades model-generated transformations to untrusted integrity while retaining maximum sensitivity and unioned origins/tenants. Both `ProvenanceGraph.derive()` and the lightweight `derive()` helper apply it; `LineageNode` rejects `source_class="model_generated"` with trusted integrity; and `TrustedMemoryAdapter.write_derived()` uses the same downgrade. Tests cover trusted-source summaries and compaction. This closes the unsafe trust-preservation behaviour for these named code paths. It does not validate semantic correctness, discover hidden context not supplied as an input, or provide a promotion mechanism for separately authenticated transform validation; no such receipt contract is currently implemented. Persistent stores produced by older versions may contain trusted `model_generated` nodes; because the label is part of each node digest and descendants refer to node IDs, the current reader rejects those records. A versioned full-DAG migration is required before using this branch with any such existing store; no migration tool is included, and a blind SQL label update is unsafe. Do not silently equate provenance continuity with semantic correctness.

A model-based semantic classifier can be measured as a supplementary signal. It is probabilistic and can miss reconstructed or encoded information; it must never be treated as a security proof or as a replacement for source lineage. Distinguish:
- lineage was preserved and the policy correctly blocked/allowed the resulting flow;
- lineage was lost by an adapter or untrusted transform;
- semantic reconstruction occurred without usable lineage;
- the source/policy oracle was ambiguous;
- the data was not in fact derived from the protected source.

The test corpus must retain both the source object and transformation metadata so results can be audited without relying on hidden model reasoning.

### 5.3 Minimum pass evidence

A passing deterministic conformance test proves only that the tested adapter preserved supplied lineage labels under the scripted transformation. The current tests also exercise an opaque model-output record with no supplied source edges and assert that it remains lineage-incomplete and cannot be promoted into a complete graph. This is a fail-closed check for missing declared lineage, not an ability to infer hidden semantic dependencies. A model-generated paraphrase/reconstruction test adds evidence about the tested model and prompt. Neither establishes perfect semantic reconstruction detection or complete coverage of latent model knowledge.

## 6. Workstream 4 — protected external commitments

### 6.1 Test sink design

Do not duplicate the existing test sink without first reusing its tested boundaries. The repository already contains:
- SQLite-backed logical-resource commits in `SQLiteAuthorityRegistry`, with a transaction-scoped active-authority check, quota charge, resource version and receipt in one database transaction.
- A PostgreSQL-backed `PostgresAuthorityRegistry` using a shared-primary transaction/lock profile; tests create independent clients and exercise commit-versus-revocation ordering.
- A Linux filesystem commit adapter with staged replacement and rollback/recovery tests; this is a local host filesystem profile, not a remote provider.
- A narrow in-process broker write mediator that binds an operation ID/idempotency key, signed commit permit and broker access receipt to the local logical-resource transaction. Its registry can return the original committed result on an exact safe retry and reject changed-operation key reuse.
- Existing tests in `tests/test_resource_commit.py`, `tests/test_postgres_authority.py` and `tests/test_broker_write_mediator.py` cover local commit/revocation races, permit replay, quota rollback, broker idempotent retry and receipt checks. New fault-injection coverage simulates a lost client response after both an in-process broker commit and a PostgreSQL shared-primary resource transaction. The PostgreSQL retry is issued through a second independent registry client using the same signed permit and broker access receipt; it must return the original version without a second effect or quota charge. This is a database-backed local/reference-sink fault schedule, not a remote network or SaaS-provider test. PostgreSQL-specific tests require `PACA_TEST_POSTGRES_DSN`; if unset, pytest skips them.

Extend those fixtures only where the required schedules are genuinely missing. The minimum research test sink must expose:
- a durable authority epoch/fencing token and a single, documented serialization point;
- request-bound principal, operation, canonical target, policy version, expiry, stable operation ID and idempotency key;
- a transaction that compares current authority and commits the logical test effect atomically, or an explicit monotonic fencing-token contract;
- a durable receipt with commit identity and observable outcome;
- fault injection before prepare, after prepare, before commit, after commit and before receipt delivery;
- independent clients/processes for concurrency and race schedules;
- a deterministic inspection method for committed state and receipt IDs.

**Important path distinction:** the direct `PACAAgentRuntime` + `FencedResourceExecutor` path mints a short-lived one-use permit for a local `write_file`/`mem_write` operation. That prevents replay of the same permit, but it is not the same contract as the broker's stable operation ID/idempotency-key plus access-receipt path. Do not infer that a fresh permit for a repeated request is a provider-side exactly-once guarantee. The broker protocol is also an in-process reference mediator and writes only to the local logical resource registry; it is not a production network broker or remote-provider commit protocol.

Use the SQLite/PostgreSQL logical-resource stores as **project-owned transactional test sinks**. Keep the local filesystem and broker profiles separate. None proves a remote provider's atomic commit, host-level universal mediation, or multi-primary/distributed failover safety. A new network-facing sink fixture is justified only if it tests a real service boundary that the current adapters do not expose.

The repository CI defines an ephemeral PostgreSQL 16 service, sets `PACA_TEST_POSTGRES_DSN`, and runs `tests/test_postgres_authority.py` in the `langgraph-postgres-checkpoint` job. A passing job therefore exercises the shared-primary authority/resource-reference tests against a real PostgreSQL service in CI, including separate registry clients and commit/revocation ordering. This is stronger than an SQLite-only unit test, but remains a single-primary test environment; it does not establish remote SaaS-provider semantics, high-availability failover safety, multi-primary consensus, or production load capacity.

### 6.2 Required schedules

- Revocation before authorization.
- Revocation after permit issuance but before dispatch.
- Revocation during a delayed in-flight request.
- Revocation racing the sink serialization point.
- Two simultaneous writes against one budget/target.
- Two retries with the same operation ID and idempotency key.
- Retry after a timeout where the first commit may have succeeded.
- Crash before commit, after commit, and before acknowledgement.
- Stale fencing token replay after a newer epoch has committed.
- Policy-version update with an old pending permit.
- Sink unavailable, state-store unavailable, clock skew or unavailable trusted time.
- Duplicate or delayed sink receipt; unknown/ambiguous outcome.

### 6.3 Claim rules

"Revoked" is effective at the sink only at the declared sink serialization point or after the sink's monotonic fencing epoch has advanced and returned verifiable evidence. A block at the PACA client before dispatch is not proof that an already in-flight call cannot commit.

Exactly-once execution is not claimed unless the sink/provider contract supports idempotent effect identity and durable outcome evidence. Otherwise report at-most-once, at-least-once, or unresolved/unknown behaviour precisely.

## 7. Workstream 5 — actual model-generated behaviour

Keep two experiments separate.

**A. Deterministic enforcement experiment.** Fixed, typed proposal sequences test the enforcement path without model-output variance. This remains the cleanest primary estimate for whether the reference monitor allows a prohibited effect under the selected policy.

**B. Model-in-the-loop experiment.** A pinned LLM generates tool proposals in response to ordinary tasks and adversarial context. Record the full visible input/output and tool-call metadata permitted by the provider and ethics/security rules, but never log hidden chain-of-thought. Run the same tasks across selected baseline configurations and PACA. Separate:
- attack success caused by model proposal generation;
- attack success caused by enforcement/bypass failure;
- benign model task failure;
- false denial or policy indeterminacy;
- provider/model/API infrastructure failure.

Use a published benchmark such as AgentDojo only within its supported task/attack coverage, and explicitly document all task adaptations. Do not treat adapter tests, dry-runs, scripted tests, or skipped credential-gated CI jobs as live model results.

The current AgentDojo runner is limited to its selected workspace read-tool mapping and supports matched no-defence, official AgentDojo `tool_filter`, and PACA conditions for an OpenAI-backed model. It captures package/platform metadata, per-condition episode durations and errors, p50/p95/p99 episode latency, error-free episode fraction, sequential measured episode rate, and PACA policy-decision telemetry. For benign task calls, it now hashes the monitor's normalized action target and matches decisions against the trusted task ground-truth manifest, reporting explicit denials, approval-required decisions and unobserved required calls separately. Its false-denial denominator is only the observed, exact action/target-matched required calls in the selected task subset; it is not a universal false-denial estimate. Attack-success scoring excludes pairs with a recorded `TaskResults.error` or an unusable message trace (missing trace, invalid final message or no final assistant message); these outcomes remain indeterminate and their reasons are reported separately. A final assistant message with no text content is counted separately, not automatically removed from the denominator: pinned AgentDojo v0.1.35 still evaluates the attack using the environment and tool-call trace when the final model output is empty. This distinction avoids dropping a case where a prohibited tool effect may already have occurred. The explicit indeterminate rule is needed because AgentDojo can also return `security=True` as a placeholder for certain skipped API/server-error cases. The report distinguishes completed from failed/interrupted runs. Sequential episode rate is not concurrent throughput; error-free episode fraction is not an SLA. Provider/API cost is not captured until billing/token-usage telemetry is joined to the run.

Live runs require a model-provider credential stored as a protected GitHub Actions secret or local environment secret. Do not commit or paste credentials into source, issues, logs or chat. If a credential is unavailable, complete the harness and dry-run validation, record the live test as blocked, and make no model-effectiveness claim.

## 8. Workstream 6 — security, utility and operational metrics

### 8.1 Primary security outcomes

- Confirmed prohibited effect rate at the sink (primary when the policy and sink permit a valid estimate).
- Attack success rate by independent scenario template and by attack family.
- Number and severity of prohibited effects (reported separately from binary scenario success).
- Bypass rate by enforcement boundary.
- Confirmed post-effective-revocation effects.
- Duplicate committed effects and usage-limit overshoot.
- Provenance/lineage loss rate under each transformation family.

### 8.2 Utility and decision outcomes

- Legitimate task completion rate.
- False-denial rate over predeclared benign opportunities. For the current AgentDojo subset, use exact ground-truth action/target matches and report explicit denials, approval-required decisions and unobserved calls separately; do not treat missing tool proposals as denials.
- Indeterminate-decision rate and cause.
- Human approval frequency and approval outcome, where a genuine approval service is tested.
- Incomplete or abandoned benign workflows.
- Policy-oracle disagreement and uncertain sink outcomes.

### 8.3 Operational outcomes

- Decision and end-to-end latency (p50, p95, p99).
- Throughput under stated concurrency and workload mix. The current AgentDojo episode rate is sequential and must not be called concurrent throughput.
- Availability and recovery time under injected component failures. The current per-run error-free episode fraction is not an SLA or long-term availability estimate.
- CPU, memory, network and durable-storage overhead.
- State growth per workflow and cleanup/retention cost.
- Pending/unresolved reservations, retries, reconciliation time and duplicate-effect rate.
- Integration/configuration burden and number of required trust assumptions.
- Cost per successful benign workflow and per prevented prohibited opportunity where billable service usage is available.

Never infer throughput from a local simulator. Use monotonic clocks, warm-up and steady-state phases, pinned hardware/region, concurrency levels, reset rules and repeated load trials. Report the environment and raw samples.

### 8.4 Experimental unit and analysis

The independent unit is the underlying workflow/attack template, not each replay, model sampling seed, or parameter variation. Keep development/pilot and confirmatory templates disjoint. Variants from one underlying attack skeleton remain clustered under one template.

Before confirmatory testing:
1. Freeze templates, policy fixtures, outcome oracle, eligible opportunities, comparator releases/configurations, test sink and reset procedure.
2. Define a primary estimand and denominator. A blocked opportunity remains in the shared denominator; it is not silently removed.
3. Predefine treatment order/randomization, invalid-trial rules and missing/uncertain outcome handling.
4. Estimate baseline event rates and template-level variation using a disjoint pilot.
5. Conduct a simulation-based power and interval-coverage analysis. The 30-template floor used in the proposal is not by itself a guarantee of adequate power; increase the sample or report exploratory/inconclusive findings.
6. Keep security, legitimate utility and systems cost as separate outcomes. Do not call utility "preserved" merely because a difference is not statistically significant.
7. Publish effect sizes, uncertainty intervals, per-family results and sensitivity bounds, including conservative treatment of uncertain sink outcomes.

The repository now includes `paca/evaluation_statistics.py`, a paired whole-template bootstrap helper. It aggregates observations into one rate per declared template, calculates the unweighted mean of treatment-minus-control rate differences, resamples whole templates with replacement, and returns a 95% percentile interval. It refuses duplicate template IDs, invalid denominators/counts and Boolean values masquerading as integers. Fewer than 30 templates are labelled exploratory-only; 30 or more are merely eligible for a separate power/protocol review. The function cannot establish that the investigator's template IDs are truly independent, cannot replace preregistration or the proposal's simulation-based power/coverage analysis, and does not handle uncertain-outcome sensitivity bounds automatically.

## 9. Test and implementation gates

| Gate | Required work | Exit condition | Stop condition |
|---|---|---|---|
| G0 — freeze | Threat model, policy family, scenario schema, evidence labels, source register, pinned baseline commit | Versioned protocol and trace schema; reviewable scope | Ambiguous policy oracle or no observable sink |
| G1 — strongest baseline | D/I audit, native artifact smoke tests, vendor deployment profiles where access exists, strongest feasible combinations | Comparator matrix includes exact semantics, versions, paths, unsupported coverage and evidence type | No feasible native interface: document D/I; do not fake a live run |
| G2 — residual gap | Matched violation reproduction after best-known minimum remedies | At least one policy-specific, in-scope, reproducible residual violation; or a documented no-gap decision | Gap exists only because a comparator was misconfigured or bypassed |
| G3 — transformation corpus | Deterministic lineage-transform tests plus model-generated variants when available | Results distinguish lineage preservation, semantic reconstruction, false denials and oracle uncertainty | No defensible source-to-derived artifact oracle |
| G4 — effect sink | Transactional/fencing sink and failure schedules | Sink receipts prove the exact commit ordering/epoch semantics under tested schedules | Sink contract cannot expose the commitment point |
| G5 — model-in-loop | Pinned model, provider, tasks and adversarial runs | Raw results separate model proposal failure from enforcement failure | Credential or reproducible model environment unavailable |
| G6 — confirmatory evaluation | Frozen disjoint templates and predeclared metrics/power | Valid estimate with uncertainty, costs and limitations | Underpowered corpus, changed rules after outcomes, or uncertain effects change result direction |

G2 is the decision gate for any additional PACA mechanism. No generic "continuous coordination" module should be added merely because it is part of the proposed architecture. The smallest policy-specific extension is designed only after the residual requirement is recorded. If no extension is justified, report the no-extension branch.

## 10. Repository implementation map

| Existing path | Role in this programme | Work required |
|---|---|---|
| `paca/bench.py` | Current deterministic simulator | Result JSON now carries schema version and `S` (project-owned simulation) evidence metadata, including explicit toy-baseline and no-live-vendor/no-model flags. Preserve as regression simulation; not industry evidence. |
| `docs/industry_comparator_matrix.json` | Machine-readable evidence register | Sixteen separately identified external vendor/research comparators plus the PACA++ candidate entry (17 register entries total) and five baseline profiles; all 16 external entries remain `D`/`not_run`. A test guards distinct research mechanisms and prevents documentation from being represented as live execution. |
| `paca/evaluation_statistics.py` | Independent-template paired estimator | Whole-template paired bootstrap and confirmatory-floor labelling are implemented with unit tests. Independent-template authoring, pilot-derived power/coverage and confirmatory runs remain outstanding. |
| `paca/baselines.py` | Hand-authored toy baselines | Keep explicitly labelled as simulations. Add adapters only for real/native product execution profiles; avoid pretending a hand-coded policy equals a vendor engine. |
| `paca/scenarios.py` | Current authored attack/benign fixtures | Existing 30 attack and 11 benign examples remain author-defined fixtures, not independent confirmation templates. Build a versioned independent workflow-template corpus with lineage transformations, multi-agent steps and sink outcomes. |
| `paca/integrations/agentdojo_benchmark.py`, `paca/monitor.py` | Existing bounded AgentDojo adapter/runner and policy audit | Runner adds per-condition latency/error/sequential-rate telemetry, explicit indeterminate classification, and trusted-manifest-matched required-call denial/approval/unobserved metrics using a target digest rather than storing raw targets in the audit. It still requires a protected model credential, has selected workspace read-tool coverage only, and does not capture provider billing cost or concurrent throughput. |
| `paca/resource_commit.py`, `paca/filesystem_commit.py`, `paca/postgres_authority.py`, `paca/broker_write.py` | Existing local logical/filesystem commit fences, PostgreSQL authority state and in-process broker writes | Existing tests now include in-process and PostgreSQL shared-primary post-commit response-loss injection followed by exact idempotent retry across independent registry clients. These are local/reference sink contracts, not remote-provider atomic effects or distributed failover. |
| `models/*.tla` | Existing bounded formal models | Add or refine only selected invariants relevant to the frozen primary policy; record TLC bounds and keep formal properties separate from runtime tests. |
| `docs/CONTAINMENT_EVALUATION.md` | Existing containment protocol, including OpenShell context | Link to this protocol and update only when new real evidence exists. |
| `docs/security-roadmap.md` | Implementation maturity and remaining gates | Keep product/production claims aligned with tested code and independent evidence. |

## 11. Reproducibility and reporting artefacts

Each experiment run must save:

- Protocol version and repository commit.
- Comparator/service release, region/tenant/host, exact configuration and policy text.
- Scenario template ID, variant ID, run ID, seed, model identifier and prompt/task version when applicable.
- Principal, tenant, task, policy version/epoch and event sequence.
- PACA and comparator decisions with reason codes.
- Sink-side receipts and before/after state.
- Monotonic timing samples and resource measurements.
- Invalid/uncertain outcome reasons.
- Raw logs with secrets and hidden model reasoning redacted.
- Result schema version, analysis code commit, and trace/result hashes.

Release only synthetic data and reviewed traces. Never publish live credentials, customer records, private prompts, unredacted provider responses, or exploit details that could enable abuse. Apply a responsible-release review before publishing any security-sensitive bypass.

## 12. Current status and immediate next actions

At this branch revision, the protocol and machine-readable comparator matrix distinguish 16 external native vendor/research mechanisms plus the PACA++ candidate (17 register entries total); the comparator JSON and evidence labels are test-guarded; the deterministic simulator is explicitly labelled `S`; synthetic lineage-conformance tests cover supplied derivation edges and fail closed for an opaque model output with missing source edges; the in-process broker and PostgreSQL authority tests include simulated post-commit response loss and exact retry across independent registry clients; the AgentDojo adapter records run status, exact-manifest required-call denials/approval/unobserved counts, and operational telemetry, and keeps errored/unusable-trace attack episodes indeterminate while reporting missing final assistant text separately; and the paired whole-template bootstrap helper rejects duplicate template IDs and labels small samples exploratory. Existing SQLite/PostgreSQL/local-filesystem/in-process broker commit, revocation and idempotency tests are mapped for reuse rather than duplicated. The six-point evaluation is **not completed**. No live vendor/service test, residual-gap reproduction against a configured strongest layered baseline, live model-generated benchmark result, external-provider commit/fencing test, or confirmatory independent-template analysis has been produced by this work.

The immediate implementation order is:

1. Pass the complete latest CI matrix and review AgentDojo indeterminate-result tests, comparator tests, lint and release validation.
2. Pin and source-audit candidate research artefacts, with DelegateGuard and Delegation Without Trust treated as primary close novelty comparators; reproduce their native implementations, baselines, attacker models and observable-sink contracts before claiming a distinct delegation/reference-monitor contribution.
3. Build a versioned, disjoint independent workflow-template corpus; retain the current 30 attack/11 benign fixtures as development/regression examples only. Predefine policy oracles, sink evidence, randomisation and sample-size/power/coverage analysis.
4. Extend the existing SQLite/PostgreSQL/filesystem/broker fault schedules only where coverage is missing; keep external-provider effects unclaimed until a real provider/sink contract and protected test environment are exercised.
5. Obtain permitted AWS, NVIDIA, Microsoft and Google environments, configure the strongest applicable native controls and test real compatible layered combinations; use D/I only where live testing is unavailable.
6. Run bounded model-in-loop and semantic-transformation experiments using credentials in protected secret storage, not chat or source. Join provider usage/billing telemetry and run concurrent/failure-load trials before claiming cost, throughput or availability.

No comparative effectiveness, superiority, commercial readiness, complete five-domain mediation, or future-incident-prevention claim is made by this protocol. The DelegateGuard and Delegation Without Trust papers are particularly close prior art: broad claims to model-independent delegation authorization, attenuable capabilities, broker-mediated tool actions, label propagation or revocation are not novel on the basis of this repository's current evidence. Any defensible contribution must be narrower and empirically distinguishable, for example by tested cross-domain state/usage semantics or resource-side commit fencing under a matched threat model.
