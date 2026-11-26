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
| Amazon Bedrock AgentCore Policy — Temporal Policies | Session-aware gateway authorization over earlier actions, approvals, sequence conditions, and count/sum-style usage within a policy session | Tool-use sequences, session usage, prior approval, target/argument correlation, gateway-mediated actions | Session ID is application supplied; temporal history is scoped to that session. Documented temporal limits include 20 temporal policies per engine, at most 3 temporal operators per policy, and a 24-hour maximum lookback. Session propagation does not cross AWS accounts or Regions. Temporal policies are documented as unavailable in Asia Pacific (Hyderabad) and available in Asia Pacific (Mumbai) at the date of this audit. |
| NVIDIA OpenShell | Isolated agent runtime, kernel-level filesystem/process/network controls, credential brokering to approved endpoints, and policy-change verification | Runtime containment, filesystem/system-call/network bypass attempts, credential exposure, policy-change regression | This is an OS/runtime containment layer, not a drop-in replacement for a workflow provenance or business-authorization PDP. The project has moved to the `ai-openshell/openshell` repository under CNCF governance. Pin an actual release/commit and supported host environment. NVIDIA Sentry/BlueField hardware claims require the actual hardware path; a software-only test cannot establish them. |
| Microsoft Entra Agent ID | Agent identity, authentication, delegated/application access, lifecycle governance, Conditional Access and related identity protections | Principal authenticity, identity/token scope, delegation and lifecycle, access to protected APIs | Identity is a prerequisite for authorization, not evidence of automatic provenance continuity, memory control, or final effect atomicity. Test it with a real protected resource/API and the configured tenant, not as though it were a standalone agent runtime. |
| Google Cloud Agent Gateway | Network entry/exit enforcement across user–agent, agent–tool and agent–agent interactions; SPIFFE-based agent identity; registry, IAM and semantic/content policy components | Tool/egress calls, MCP/A2A communication, destination restrictions, content screening, network-layer observability | Test only paths actually routed through the gateway. Do not infer visibility into unmediated internal memory or model planning. Record which policy component (IAM, Model Armor, Semantic Governance, or custom Service Extension) produced each decision. |
| Palo Alto Prisma AIRS (contextual comparator) | Broader AI application/runtime protection and threat controls | Runtime threat detection, prompt injection, sensitive-data and model/application security | Include in documentary context or a separate live profile only where the required product features and test interfaces are available. It is not assumed to expose a deterministic authorization API comparable to the project PDP. |
| MCP runtime-policy PEP (Wang, Zhu and Li, 2026) | Tool-call boundary enforcement, per-trace source-integrity/data-sensitivity labels, cross-step propagation and tamper-evident decisions | MCP call mediation, data-flow labels, cross-step provenance, attack/false-negative reproduction | A close research comparator. The proposal's cited evaluation uses a prototype and limited real-MCP validation. Inspect and smoke-test the exact repository commit before including it in a matched runtime comparison. |
| Progent | Symbolic tool-privilege constraints and argument checks | Tool choice, arguments, privilege attenuation and expansion | Do not generalize its results to memory or terminal effects unless the exact artefact and interfaces demonstrate those paths. |
| CaMeL / Multi-CaMeL | Separation of trusted control/data and cross-agent provenance concepts | Provenance, trusted/untrusted data separation, cross-agent transfer | Native architecture may not accept the project's fixed scripted proposals without semantic changes. If not, report its native results separately and do not force it into the paired harness. |
| Sapien / FORGE / VIGIL / AgentSpec | Stateful, event/trace, runtime and behavioral policy enforcement | Temporal dependencies, event history, action constraints, enforcement points | Select only after source and artefact status, declared semantics, and feasible mediation have been checked. |
| CapLease / AID-Guard and related commit/retry work | Durable authorization, usage/reservations, request-to-effect binding, commit/recovery semantics | Concurrent usage, retries, revocation, effect identity and uncertain outcomes | These mechanisms make generic claims of novel commit-time authorization, reservations or retry safety indefensible without a narrower residual property. |

### 3.2 Documentary source register (reviewed 26 November 2026)

- AWS Temporal Policies: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html
- AWS policy sessions and identity propagation: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-session-based-temporal.html
- AWS quotas: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
- NVIDIA OpenShell repository: https://github.com/ai-openshell/openshell
- NVIDIA OpenShell product overview: https://build.nvidia.com/openshell
- Microsoft Entra Agent ID documentation: https://learn.microsoft.com/en-us/entra/agent-id/
- Microsoft agent identity concepts: https://learn.microsoft.com/en-us/entra/agent-id/agent-identities
- Google Agent Gateway overview: https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview
- Prisma AIRS AI Runtime Security: https://www.paloaltonetworks.com/resources/datasheets/ai-runtime-security
- MCP PEP paper: https://doi.org/10.3390/electronics15132829
- MCP PEP artefact: https://github.com/wilesanGH/mcp-pep-agent-security

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
| B2-Research | Each eligible research artefact in its pinned native configuration; a separate reproduction only when clearly labelled | Research prior-art profile |
| B3-Layered | Strongest technically compatible combination of identity, gateway/temporal enforcement, runtime isolation and provenance/authorization controls | Best-available layered baseline |
| P | PACA configuration under evaluation | Candidate treatment, not presumed better |

A system is eligible for a paired quantitative comparison only if the scenario reaches the system's native enforcement path without bypassing or changing the system's semantics and the final effect can be observed. If the systems cannot accept the same fixed proposal, compare their native workflows in a separate stratum; do not pool those results with B/P estimates.

The B3 profile is assembled from controls that can actually interoperate under the declared deployment assumptions. Do not assume Entra identity tokens automatically become Google SPIFFE identities, that AWS WAT context survives arbitrary gateways, or that multiple network gateways can be stacked without changing routing/identity behaviour. Prove each integration in a smoke test and record the translation boundary. A theoretical product combination is not an executed baseline.

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

A model-based semantic classifier can be measured as a supplementary signal. It is probabilistic and can miss reconstructed or encoded information; it must never be treated as a security proof or as a replacement for source lineage. Distinguish:
- lineage was preserved and the policy correctly blocked/allowed the resulting flow;
- lineage was lost by an adapter or untrusted transform;
- semantic reconstruction occurred without usable lineage;
- the source/policy oracle was ambiguous;
- the data was not in fact derived from the protected source.

The test corpus must retain both the source object and transformation metadata so results can be audited without relying on hidden model reasoning.

### 5.3 Minimum pass evidence

A passing deterministic conformance test proves only that the tested adapter preserved supplied lineage labels under the scripted transformation. A model-generated paraphrase/reconstruction test adds evidence about the tested model and prompt. Neither establishes perfect semantic reconstruction detection or complete coverage of latent model knowledge.

## 6. Workstream 4 — protected external commitments

### 6.1 Test sink design

Build a dedicated, resettable test resource/sink with:
- a durable authority epoch/fencing token;
- request-bound principal, operation, canonical target, policy version, expiry, operation ID and idempotency key;
- an atomic serialization point that checks the current epoch and commits the test effect in one transaction or enforces a monotonically increasing fencing epoch;
- a durable sink receipt with commit identity and observed outcome;
- fault injection before prepare, after prepare, before commit, after commit and before receipt delivery;
- independent clients/processes to create real concurrency;
- a deterministic inspection endpoint that reports committed state and receipt identifiers.

Use PostgreSQL or an equivalent transactional store as a test sink. Keep the local logical resource executor and filesystem fence as separate profiles; neither establishes a remote provider's semantics.

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
- False-denial rate over predeclared benign opportunities.
- Indeterminate-decision rate and cause.
- Human approval frequency and approval outcome, where a genuine approval service is tested.
- Incomplete or abandoned benign workflows.
- Policy-oracle disagreement and uncertain sink outcomes.

### 8.3 Operational outcomes

- Decision and end-to-end latency (p50, p95, p99).
- Throughput under stated concurrency and workload mix.
- Availability and recovery time under injected component failures.
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
| `paca/bench.py` | Current deterministic simulator | Preserve as regression simulation; do not relabel toy models as vendor products. Add versioned machine-readable result records and separate evaluation modes. |
| `paca/baselines.py` | Hand-authored toy baselines | Keep explicitly labelled as simulations. Add adapters only for real/native product execution profiles; avoid pretending a hand-coded policy equals a vendor engine. |
| `paca/scenarios.py` | Current authored attack/benign fixtures | Add versioned workflow templates, source/derived artifact relations, transformation operations, multi-agent steps and sink outcomes. Mark dependencies/variants by independent template ID. |
| `paca/integrations/agentdojo_benchmark.py` | Existing bounded AgentDojo adapter/runner | Extend only within actual supported tasks and benchmark APIs; retain task exclusions and credential-gated live execution. |
| `paca/resource_commit.py`, `paca/filesystem_commit.py`, `paca/postgres_authority.py` | Existing logical/filesystem commit fences and PostgreSQL authority state | Build separate protected test-sink profiles and concurrency/fault schedules; do not conflate local resource commits with remote provider transactions. |
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

At this commit, the documentary source register and the execution protocol are prepared. The local project simulation and existing AgentDojo adapter exist, but the six-point evaluation is **not yet completed**.

The immediate implementation order is:

1. Update the result schema and benchmark labels so toy simulation, source audit, artefact reproduction and live vendor runs cannot be mixed.
2. Build the frozen transformation/lineage scenario corpus with independent template IDs and benign controls.
3. Build the transactional test sink and fault/concurrency schedules on top of the existing authority/commit interfaces.
4. Implement vendor-native adapters/profile harnesses only for services the operator can access; maintain D/I evidence records for the rest.
5. Extend the model-in-the-loop runner and capture raw AgentDojo results when a protected provider credential and valid task scope are configured.
6. Add cluster-aware analysis and latency/throughput/availability/cost reporting; freeze confirmatory rules after pilot evidence.

No comparative effectiveness, superiority, commercial readiness, complete five-domain mediation, or future-incident-prevention claim is made by this protocol.
