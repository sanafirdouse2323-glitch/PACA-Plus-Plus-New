# PAC++ New: Agent-Lifecycle Security Research Programme

**Research scope:** security of LLM-based agents across their lifecycle.  
**Repository boundary:** this document applies only to `PACA-Plus-Plus-New`. It does not define or implement the enterprise gateway project in the separate `PACA-Plus-Plus` repository.  
**Research status:** proposed research architecture and work programme, not a completed implementation or validated security guarantee.  
**Implementation snapshot:** 26 November 2026, `main` commit `2296151482dff4246e21cec54a89786e22aa0aff`. Research claims and hypotheses below remain unvalidated until independently evaluated.

## 1. Research objective

PAC++ New studies how security-relevant information and authority propagate through an LLM agent over time. The target is not merely to decide whether an isolated tool call is allowed. It is to determine whether an agent's evolving state, memory, plans, delegated work, messages and proposed effects remain consistent with the user's authorised task and the system's current policy.

The central problem is **lifecycle continuity**:

- untrusted information can influence a plan without appearing in the final tool arguments;
- a memory write can preserve an attack after the original input disappears;
- a summary or transformation can obscure the source of a value;
- a downstream agent can misinterpret data received from another agent as trusted instruction;
- a capability can remain usable after the task, policy or delegation context that justified it has changed; and
- an action can be authorised at planning time but executed later with changed arguments, state, recipient, tool implementation or policy.

The research goal is to define, implement and evaluate a reference-monitor architecture that tracks both **information provenance** and **authority provenance** across those transitions, and re-evaluates usage constraints at each security-relevant transition.

This is a systems-security problem. Model alignment, prompt wording and injection classifiers may be useful defence-in-depth, but they are not the authority boundary.

## 2. What the current repository actually contains

The code on `main` is a substantial but partial research prototype. The table describes implementation scope, not independently verified security guarantees.

| Component | Present implementation | Boundary |
|---|---|---|
| Provenance | `Label`, `Arg`, explicit `derive()`, typed `LineageNode`/`ProvenanceGraph`, and `SQLiteProvenanceRepository` for durable lineage metadata | Source identity and labels are supplied by trusted adapters. The system does not infer every hidden model-context dependency or prove that a source is truthful. |
| Memory | Separate `SQLiteMemoryValueStore` and `TrustedMemoryAdapter`; checks authority, tenant, purpose, lineage and digests before returning values | Raw database/store access bypasses the adapter. Provenance metadata and values are local SQLite stores, not one distributed transaction. |
| Authority | `SQLiteAuthorityRegistry`, HMAC and Ed25519 capability envelopes, static Ed25519 verification-key rings for key overlap/retirement, policy epochs, revocation, delegation checks, per-capability counters, message receipts and tenant/task aggregate quotas | Identity and task callbacks are trusted host integrations. OIDC/workload identity, KMS/HSM custody, authenticated key distribution and coordinated production rollover remain open. |
| Shared authority | Optional `PostgresAuthorityRegistry` shares authority, revocation, counters, aggregate quota, message receipts and local resource-commit state across clients on one primary | Not multi-primary, rollback-safe failover or replication of provenance, memory values and the Monitor operation ledger. |
| Runtime and monitor | Selected action/target policies, strict consequential-monitor validation, effect tokens, protected runtime checks and an opt-in local resource-commit fence for `write_file`/`mem_write` | Only actions routed through the configured runtime are mediated. The local commit fence does not cover remote providers or every executor. |
| Framework adapters | AgentDojo ToolsExecutor and limited workspace mapper; LangGraph BaseStore; LangChain middleware; PostgreSQL checkpoint wrapper | Adapters do not intercept direct calls to raw tools, stores, checkpointers, databases or alternate execution paths. |
| Provider ingress | Read-only Gmail, Microsoft Graph mail, Slack history and Qdrant search adapters with bounded HTTP handling and provenance capture | CI uses mocked HTTP. Production identity binding, live account validation, provider writes, deletion sync and remote commit fencing remain open. |
| Execution helpers | Optional Docker worker; Linux `openat2` filesystem and DNS/IP-pinned network primitives | Docker isolation is opt-in. Filesystem/network helpers are not wired into every connector or executor. |
| Formal models | Bounded `PACAAuth.tla` and `PACALifecycle.tla` models with TLC configurations | TLC checks finite specifications; it does not prove Python refinement, host isolation or deployed-system security. |
| Evaluation | Author-written deterministic simulator, regression tests, protocol fixtures and a limited AgentDojo runner | Not an independent benchmark or completed live-agent effectiveness evaluation. |
| Reference API | `paca_executor.py` exposes `/health` and `/decide` for local demonstration | It accepts demonstration capability data and never executes external effects. It is not a production enforcement service. |

The separate `SQLiteOperationLedger` in `paca/ledger.py` persists selected Monitor operation/token state. It is distinct from the authority registry and from the provenance/value stores. These stores have different transaction boundaries and must not be described as one unified distributed database.

These components support the research question, but their presence does not establish complete lifecycle mediation. See [the current implementation roadmap](security-roadmap.md), [the durable implementation record](DURABLE_LIFECYCLE_SECURITY.md) and [the direct-bypass evaluation](DIRECT_BYPASS_EVALUATION.md) for the specific interfaces and residual paths.
## 3. Research landscape and positioning

The literature rules out several overly broad novelty claims.

### 3.1 Tool-call privilege control and information-flow enforcement

- **CaMeL, “Defeating Prompt Injections by Design”** separates trusted control flow from untrusted data, tracks value-level capabilities and checks data flows at tool calls. Its reported AgentDojo results and SaTML 2026 publication make it a direct comparator. PAC++ New must not claim to be the first capability- or provenance-aware agent monitor. [Paper](https://arxiv.org/abs/2503.18813) · [SaTML 2026 publication](https://ieeexplore.ieee.org/abstract/document/11691650/authors)
- **Progent** generates and updates symbolic privilege policies and uses an SMT check to distinguish policy narrowing from expansion, enforcing monotonic confinement unless an expansion is approved. PAC++ New must not present dynamic tool-scope policy or monotonic privilege narrowing alone as novel. [Paper](https://arxiv.org/abs/2504.11703)
- **AgentDojo** supplies a dynamic tool-using environment with 97 tasks and 629 security test cases; it is an evaluation baseline, not a complete lifecycle assurance proof. [NeurIPS 2024](https://papers.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html)
- **Agent Security Bench (ASB)** covers multiple domains, tools, attack/defence methods and metrics, including memory and planning attacks. It is a complementary benchmark source. [ICLR 2025](https://mlanthology.org/iclr/2025/zhang2025iclr-agent/)
- **AgentDyn** highlights that static tasks can under-test dynamic replanning, helpful third-party instructions and open-ended utility. It motivates dynamic, multi-step evaluation rather than relying only on fixed tool-call sequences. [2026 preprint](https://arxiv.org/abs/2602.03117)

### 3.2 Persistent memory and delayed compromise

- **AgentPoison** demonstrates backdoor attacks through poisoned long-term memory and knowledge bases. [NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html)
- **MPBench / “From Untrusted Input to Trusted Memory”** analyses four memory-write channels and six attack classes, and reports that prompt-injection defences do not adequately cover memory poisoning. It is a direct comparator for memory security. [2026 preprint](https://arxiv.org/abs/2606.04329)

### 3.3 Multi-agent provenance and boundary laundering

**“Can CaMeLs Talk?” (October 2026)** reports that individually protected agents do not automatically compose: untrusted data can be reinterpreted as trusted input at an agent boundary. Its multi-CaMeL protocol separates trusted instructions and untrusted data in inter-agent communication. PAC++ New must treat this as existing work and compare with it; it cannot claim first cross-agent provenance preservation. [2026 preprint](https://arxiv.org/abs/2610.05640)

### 3.4 Lifecycle-wide evidence gaps

A June 2026 survey of 247 papers identifies persistent state, information flow and delegated authority as interacting lifecycle concerns, and notes comparatively thin work on provenance, revocation, inter-agent trust and topology-aware containment. [Survey](https://arxiv.org/abs/2606.10749)

A structured review published 10 November 2026 specifically examines authorization assurance for tool-using agents. Its corpus-bounded findings report gaps in evaluated revocation assurance, delegation containment, trajectory-wide effective privilege and the distinction between correct final state and correctly authorized execution. These findings are scoped to that review's corpus; they are not proof that no such work exists anywhere. [Review](https://link.springer.com/article/10.1007/s10207-026-01343-w)

The OWASP Top 10 for Agentic Applications 2026 independently identifies goal hijack, tool misuse, identity/privilege abuse, supply-chain risks, memory/context poisoning, insecure inter-agent communication, cascading failures and rogue agents among its risk categories. [OWASP 2026](https://genai.owasp.org/top-10-for-agentic-applications-2026/)

**Positioning conclusion:** “secure the whole agent lifecycle”, “use provenance”, “use capabilities”, and “mediate tool calls” are not, individually, novel contributions. A defensible research contribution must specify a narrower mechanism, its invariants, the lifecycle transitions it covers, and experiments that distinguish it from CaMeL, Progent, multi-CaMeL and memory-security baselines.

## 4. Proposed research direction: provenance-conditioned authority continuity

The working research direction is **UCAUM — Unified Continuous Authorisation and Usage-Control Model**. The name is a project label, not a claim of novelty or a standard.

The candidate contribution is a formal and executable model in which information provenance and delegated authority are tracked as related but distinct histories. Every lifecycle transition that can change information, authority or an external effect is checked against the current task, principal, policy version and state.

The specific hypothesis is:

> A monitor that preserves provenance and authority lineage across memory reuse, planning, delegation and communication, and revalidates them at the point of each consequential transition, will prevent classes of delayed and cross-agent policy violations that are not detected by isolated tool-call checks, while retaining measurable benign-task utility.

This hypothesis must be tested. It is not an established result.

### 4.1 Two linked graphs, not one overloaded label

**Information provenance graph.** Each data object has a stable object/version identifier and a lineage record describing:
- source and authenticated source identity, where available;
- source class and trust status (user instruction, organisation policy, external content, tool output, memory, peer-agent message, model-generated content);
- tenant and sensitivity, including explicit unknown/mixed ownership;
- parent objects and transformation events;
- purpose, retention/expiry and freshness where the source provides meaningful semantics;
- integrity/confidentiality labels and any explicit, authorised declassification event.

**Authority lineage graph.** Each capability records:
- authenticated principal/agent identity and tenant;
- task and purpose;
- permitted action/effect types and resource predicates;
- constraints on data provenance and destinations;
- parent capability and delegation chain;
- expiry, use budget, policy epoch and revocation state;
- required approval conditions and evidence identifiers.

Do not conflate the two. Data being trusted does not grant authority; having authority does not make data trusted.

**Typed reference semantics merged on `main` (these are building blocks, not universal mediation):**

- `paca.provenance.LineageNode` represents one immutable object/version record. It carries a trusted-adapter source identifier and source class, SHA-256 content digest, conservative `Label`, parent node IDs, transformation name and optional purpose. `ProvenanceGraph` records nodes in memory, requires parents to exist before children, rejects object/version reuse with different metadata, and rejects transformations that upgrade integrity or erase sensitivity, origins, tenant lineage or unknown-tenant state.
- `Arg.lineage_refs` carries optional references to those nodes, and `lineage_incomplete` marks a derived value when any dependency lacked an explicit lineage reference. The global `derive()` helper preserves the union of references and propagates incompleteness; `ProvenanceGraph.derive()` rejects incomplete inputs and records an explicit transformation node. Values without lineage references remain supported for backward compatibility and are not silently claimed to have complete provenance.
- `paca.authority.AuthorityLineage` is a separate immutable capability-grant snapshot. Delegated records carry the digest of their parent's complete authority chain. `AuthorityLineageGraph` requires parent-first insertion and verifies that digest before checking tenant/task continuity, exact purpose continuity, non-decreasing policy epoch, non-extending expiry and conservative grant-scope attenuation.
- `Capability` validates that its principal, tenant, task, grant scope, expiry and parent-presence agree with its attached authority record. `Request.digest` now binds argument lineage references, resource lineage references and the complete authority record as well as the existing argument labels and capability fields.

**Persistence and enforcement limits:** `ProvenanceGraph` and `AuthorityLineageGraph` are in-memory semantic helpers. Related lineage metadata and authority records are persisted by separate SQLite repositories/registries, with optional PostgreSQL support for authority state on one primary. Memory values, provenance metadata and the Monitor operation ledger remain separate SQLite stores; there is no cross-store atomic transaction. Trusted connectors and application callbacks still supply source identity, labels and task context. The adapters do not automatically instrument all model context, arbitrary framework state, direct resource access or remote effects. A digest binds the supplied bytes and metadata; it does not prove the source was truthful. Production OIDC/workload identity, protected KMS/HSM key custody and coordinated key distribution/rollover, mandatory process isolation, destination-side commit authorization and independent security evaluation remain open.

### 4.2 Lifecycle state and transition checks

Represent the runtime as a sequence of typed events:

`e_t = (actor, stage, operation, object_versions, provenance_refs, capability_ref, policy_epoch, effect_ref, outcome)`

The state is:

`X_t = (P_t, A_t, M_t, D_t, C_t, E_t, R_t)`

where `P` is provenance state, `A` is authority/delegation state, `M` is memory state, `D` is pending plan/decision state, `C` is communication state, `E` is the effect/operation history, and `R` is revocation/policy-version state.

A transition is accepted only if its preconditions hold and the state update preserves the invariants. A model-generated plan is an untrusted proposal; it is never itself an authorization credential.

| Lifecycle transition | Required security behaviour |
|---|---|
| Input and observation | Attach source identity and provenance before content enters the agent's usable context; distinguish trusted instructions from external data |
| Retrieval and memory read | Authorise before releasing stored content; retrieve its original lineage and version; enforce tenant, purpose, freshness and revocation constraints |
| Derivation and summarisation | Preserve dependency lineage; if dependencies cannot be established, use a conservative unknown/untrusted label rather than silently upgrading trust |
| Memory write, compaction and proceduralisation | Treat all write channels as security-sensitive; record writer, source lineage, transformation, policy and task; prevent untrusted content from becoming privileged instruction or procedure |
| Planning and action selection | Record plan provenance and dependencies; treat plans as proposals; re-evaluate the selected action rather than trusting the model's explanation |
| Delegation | Issue a child capability no broader than the parent; bind it to the receiving agent, subtask, purpose, data constraints, expiry and revocation chain |
| Inter-agent communication | Preserve authenticated sender, message type, provenance and authority separately; prevent data from becoming trusted instructions merely because an agent forwarded it |
| Tool execution and external effect | Validate exact action, complete arguments, destination, resource version, tool identity, capability status and current policy immediately before the effect |
| Revocation and recovery | Reject stale capabilities; propagate revocation through descendants; identify memory and derived objects affected by compromised sources; quarantine/re-evaluate rather than silently trusting old state |

### 4.3 Candidate invariants

These are proposed properties to formalise and test, not currently proven guarantees.

1. **No provenance upgrade by transformation:** summarising, embedding, storing, retrieving or forwarding content does not increase its trust or erase its source lineage without an explicit, authorised declassification event.
2. **Memory lineage preservation:** a memory read returns the stored object's current provenance and version; a missing or inconsistent record fails closed.
3. **No authority from content:** external content, tool output, memory entries and peer-agent messages cannot mint or expand capabilities.
4. **Delegation attenuation:** every child capability is a subset of the parent's authority under a clearly defined order over actions, resources, purpose, time and constraints.
5. **Revocation closure:** after a capability or trust source is revoked, no descendant capability or derived state may authorise a protected effect unless a new trusted authorisation explicitly re-establishes it.
6. **Plan is not permit:** a plan, chain-of-thought, tool suggestion or model assertion cannot substitute for an independently checked authorization decision.
7. **Effect binding:** the executed operation must match the action, complete effect-relevant arguments, destination, tool identity, object versions and policy epoch that were checked.
8. **Complete mediation within declared scope:** every path to each declared protected effect crosses an enforcement point; unknown or unmapped effect paths are denied or explicitly excluded from the claim.
9. **Tenant and purpose isolation:** combining or relaying data cannot erase mixed/unknown tenant provenance or silently broaden the allowed purpose.
10. **Recovery evidence:** after a suspected compromise, the system can identify affected lineage and authority descendants and can demonstrate containment/recovery outcomes.

The partial order for delegation and the semantics of declassification need precise definitions before implementation. “Subset” over glob strings alone is not a sufficient formal definition.

## 5. What is distinctive enough to investigate

The strongest candidate is not another generic tool firewall. It is the interaction of:

1. **Temporal provenance:** how the origin and validity of information survive memory writes, compaction, summarisation, retrieval and re-use across tasks.
2. **Authority continuity:** how task-scoped authority is created, narrowed, delegated, renewed and revoked as the agent's state changes.
3. **Cross-transition composition:** whether individually reasonable memory, tool, planning and communication controls still preserve their guarantees when composed.
4. **Effect-level evidence:** whether a forbidden effect was actually prevented, not merely whether a policy returned deny or the final task state looked correct.

The research should investigate delayed activation and cross-agent boundary laundering as first-class attack paths. It should not claim these attacks are new; it should define a unified state/authority model and test whether the model prevents them under explicit assumptions.

## 6. Evaluation programme

Use external benchmarks and a separately authored lifecycle extension. Do not rely on the repository's self-authored 30 attack simulations as the primary evidence.

### 6.1 Baselines

At minimum compare:
- no defence / unguarded agent;
- AgentDojo's built-in `tool_filter` where supported;
- a least-privilege tool gate (including a faithful Progent-style comparator where feasible);
- CaMeL where its architecture and task compatibility permit;
- multi-CaMeL or its published protocol for inter-agent provenance scenarios;
- a generic sandbox-style scoped-permission comparator for a narrowly defined execution-containment baseline;
- NVIDIA OpenShell as an external runtime-containment baseline, with NVIDIA Sentry evaluated separately only if the required BlueField hardware is available;
- an explicitly identified OpenAI-hosted Agents API environment or a documented self-hosted environment, not an ambiguous "OpenAI sandbox" label;
- PAC++ New ablations: provenance only, authority only, lifecycle checks without revocation, and the complete proposed model.

**Baseline status:** `SandboxScoped` remains a hand-authored toy comparator, not OpenShell, Sentry or an OpenAI environment. PAC++ New includes deterministic cross-session-artifact and cross-tenant protocol fixtures, but no vendor sandbox integration. Real external baselines require pinned runtime versions, configurations and executor adapters. See [Sandbox and External-Containment Evaluation Protocol](CONTAINMENT_EVALUATION.md). Do not label a simplified local approximation as the original system.

### 6.2 Benchmark coverage

- AgentDojo: tool-mediated indirect prompt injection and benign utility.
- ASB: broader attack/defence categories, including memory and planning.
- AgentDyn: dynamic replanning and helpful third-party instructions.
- MPBench: memory-write channels and delayed memory poisoning.
- MultiAgentDojo: multi-agent communication and boundary-laundering cases, subject to availability and reproducibility.
- PAC++ New lifecycle extension: cross-session memory reuse, compaction/procedural memory, capability renewal/revocation, delegated subtask chains, message forwarding and policy changes mid-trajectory.

Do not assume all benchmark packages or compatible task IDs are installed. Discover exact versions, interfaces and supported tasks before implementation.

### 6.3 Required metrics

Report at least:
- unauthorized protected-effect rate and attack success rate;
- cross-session artifact influence, cross-tenant value-release and provenance-retention rates;
- credential exposure, unauthorized egress, redirect/DNS-rebinding success and executor-bypass rates;
- detection and containment latency, including explicit failure of the supervisor or stop mechanism;
- benign task success and task utility under attack;
- false blocks and unnecessary approval rate;
- effective privilege over the full trajectory (granted, available, requested and exercised authority);
- memory poisoning persistence and delayed-trigger success;
- revocation latency and stale-authority success after revocation;
- delegation escape/attenuation violations;
- cross-agent provenance-loss/boundary-laundering rate;
- recovery/quarantine coverage and time to containment;
- policy latency, end-to-end latency and model/tool cost;
- errors, timeouts, unsupported tasks and skipped samples.

Use paired tasks, fixed model/version/configuration, repeated trials where stochasticity matters, confidence intervals and raw per-task traces. Separate security from utility. A correct final environment state is not enough: verify that identity, consent, ordering, policy version, delegation and approval were valid at the time of each effect.

## 7. Formal and implementation plan

### Phase A — Baseline audit and threat model
- Freeze a precise lifecycle boundary and enumerate all data, state, authority and effect transitions.
- Build an adapter coverage matrix for the simulator and AgentDojo.
- Identify trusted computing base, attacker capabilities, non-goals and explicit exclusions.
- Record the current monitor's exact checks and the gaps between simulator and real framework execution.

### Phase B — Provenance and authority semantics
- Define typed provenance records and stable object/version identifiers.
- Define capability order, delegation attenuation, purpose constraints and policy epochs.
- Define memory write/read/compaction/retrieval semantics and explicit declassification.
- Add property-based tests for label joins, lineage preservation and authority narrowing.

### Phase C — Lifecycle reference runtime
- Add an instrumented lifecycle event interface for input, memory, planning, decision, delegation, communication, tool call, effect and recovery.
- Enforce memory access before data release and memory write before persistence.
- Treat plan output as a proposal and re-authorise the chosen action at execution.
- Add authenticated agent identities and typed inter-agent envelopes; compare against multi-CaMeL rather than inventing a competing channel format without evidence.
- Add revocation propagation and recovery/quarantine for dependent memory and delegated capabilities.
- Keep filesystem/network helpers as effect-boundary components; integrate them only where the declared agent tools need them.

### Phase D — Formal specification
- Extend TLA+ (or a complementary formalism where appropriate) to model provenance objects, memory transitions, policy epochs, revocation, delegation graphs, inter-agent messages and effect commits.
- Check invariants under concurrency, retries, crashes and stale-state transitions.
- Add explicit adversarial actions: wrong tenant, altered digest, revoked parent, untrusted-to-trusted memory promotion, cross-agent relabelling, changed tool identity and bypass path.
- Define refinement obligations linking each model transition to Python code and tests. TLC passing alone is not proof that the implementation refines the model.

### Phase E — Adversarial evaluation
- Reproduce selected public benchmark baselines first.
- Add lifecycle-extension cases for delayed activation, multi-hop delegation, message forwarding, memory compaction and mid-task policy revocation.
- Test direct bypasses around adapters, including alternate tools and framework paths.
- Publish raw traces and a transparent coverage/limitations table.

### Phase F — Assurance and release
- Make claims only for instrumented paths and measured threat models.
- Require independent review of the threat model, policy semantics, adapters and evaluation scripts.
- Keep the reference/demo API explicitly separate from a trusted production authorization issuer or executor.

## 8. Explicit non-goals and separation from the sibling repository

PAC++ New is not the enterprise authorization gateway. It must not absorb the sibling project's FastAPI/OPA/PostgreSQL gateway, JWT/OIDC service, tenant RLS deployment, gateway UI, enterprise onboarding or production gateway roadmap.

PAC++ New may use authenticated identity or an external protected resource as an assumption or integration boundary in experiments, but its research contribution is the agent's lifecycle state, provenance, authority, memory, communication, planning and effect transitions.

The SQLite ledgers, secure filesystem/network primitives and bounded authorization models are supporting components, not the research contribution by themselves. Keep the scope on lifecycle continuity and do not duplicate the separate enterprise gateway or build a generic transaction platform here.

## 9. Decision gates and claim discipline

Do not call PAC++ New “complete lifecycle protection” until:
- every in-scope lifecycle transition is inventoried and instrumented;
- memory, communication, planning, delegation and effect bypasses have negative tests;
- provenance and authority continuity survive restart and cross-agent handoffs;
- revocation is tested against already-issued descendants and previously stored derived state;
- benchmark baselines and lifecycle-specific attacks are reproduced;
- formal properties are linked to implementation tests; and
- the residual trusted components and excluded paths are documented.

Until then, describe it as a **research prototype for provenance-aware, capability-based authorization across selected LLM-agent lifecycle boundaries**.

## 10. Selected references

1. Debenedetti et al., [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://papers.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html), NeurIPS 2024.
2. Debenedetti et al., [Defeating Prompt Injections by Design (CaMeL)](https://arxiv.org/abs/2503.18813), 2025; SaTML 2026.
3. Shi et al., [Progent: Programmable Privilege Control for LLM Agents](https://arxiv.org/abs/2504.11703), 2025.
4. Zhang et al., [Agent Security Bench (ASB)](https://mlanthology.org/iclr/2025/zhang2025iclr-agent/), ICLR 2025.
5. Chen et al., [AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases](https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html), NeurIPS 2024.
6. Li et al., [AgentDyn: A Dynamic Open-Ended Benchmark for Evaluating Prompt Injection Attacks](https://arxiv.org/abs/2602.03117), 2026.
7. Dash et al., [From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents](https://arxiv.org/abs/2606.04329), 2026.
8. Ling et al., [Toward Secure LLM Agents: Threat Surfaces, Attacks, Defenses, and Evaluation](https://arxiv.org/abs/2606.10749), 2026.
9. Peters-Gill et al., [Can CaMeLs Talk? Securing Multi-Agent Systems Against Indirect Prompt Injection Attacks](https://arxiv.org/abs/2610.05640), 2026.
10. Elmasry, [Authorization assurance for tool-using LLM agents: a structured review of enforcement semantics and effect-level security evidence](https://link.springer.com/article/10.1007/s10207-026-01343-w), published 10 November 2026.
11. OWASP, [Top 10 for Agentic Applications 2026](https://genai.owasp.org/top-10-for-agentic-applications-2026/).

This is a selected, non-exhaustive reading list, not a systematic literature review. Novelty, completeness and comparative claims require further verification.


## 11. Implementation status — merged main snapshot (26 November 2026)

The former `security/roadmap-phase-1` and `security/aggregate-task-quota` implementation work is now merged into `main`. `main` includes the following selected reference implementations:

- **Durable provenance and memory:** `SQLiteProvenanceRepository` persists immutable object/version lineage nodes, parent edges, authority bindings and revocations; `SQLiteMemoryValueStore` stores canonical JSON values separately; `TrustedMemoryAdapter` checks authority, tenant, purpose, ancestry, revocation and content digests before returning protected values. These stores remain local SQLite components.
- **Authenticated authority and quotas:** `HMACCapabilityAuthority` and `Ed25519CapabilityAuthority` issue audience-bound credentials. Ed25519 supports a private-key issuer, public-key-only verifier and static key-ID verification rings that permit old/new key overlap and explicit retirement for capability tokens and resource-commit permits. SQLite provides local authority state; optional `PostgresAuthorityRegistry` shares authority, revocation, capability usage, aggregate task quotas, message receipts and local resource-commit state across cooperating clients on one primary. KMS/HSM custody, authenticated key distribution, coordinated production rotation, OIDC/workload identity, multi-primary consistency and rollback-safe failover remain open.
- **Selected memory and framework mediation:** LangGraph `BaseStore` and PostgreSQL checkpoint adapters, LangChain sync/async tool middleware and the AgentDojo ToolsExecutor integration mediate explicitly wired operations. They require trusted callbacks, explicit application registration and protected host-side storage/credentials. They do not instrument every hidden model-context dependency or prevent direct access to raw stores, checkpointers or tool functions.
- **Provider ingress:** optional read-only Gmail, Microsoft Graph, Slack and Qdrant connectors capture provider results as untrusted, digest-bound provenance. CI uses mocked HTTP transports; it does not validate live user accounts or tenant identity. Qdrant search now requires a trusted `tenant_id`, injects a non-removable tenant payload filter, verifies the returned tenant marker, and checks that the memory connector's tenant matches the capture. The host must derive the configured tenant from authenticated identity, and the Qdrant write-side permission model must prevent tenant-marker forgery. Per-tenant collections and credentials are stronger where that guarantee cannot be made.
- **Strict consequential monitor profile:** the standard Monitor validates the semantic integrity of the required packaged security rules and rejects all ablation settings for consequential integrations. `PACAAgentRuntime` checks the profile at construction and before each effect; AgentDojo checks it at adapter construction and before each dispatch. This does not turn caller-supplied identity, provenance, policy or tool-mapping callbacks into independently authenticated services.
- **Local effect and execution controls:** the optional Docker worker adapter provides a constrained command-mapped container; the opt-in resource-commit adapter fences local `write_file`/`mem_write` commits against the same authority database used for revocation and quotas. Strict resource-fence mode now accepts only the exact built-in logical or filesystem executor type, binds the executor to the runtime's authority and registry clients, and dispatches built-in sync/async methods; filesystem adapter configuration is sealed after initialization. Logical values and filesystem recovery sidecar state use separate internal registry key namespaces, and append-only committed-version evidence supports safe journal recovery when another backend later writes the same public resource target. Neither makes process isolation mandatory for every executor or provides a remote-provider commit protocol.
- **Broker provenance freshness:** read disclosure and write commit now hold a local SQLite provenance revocation guard while trusted callbacks validate source lineage and the protected operation completes. This orders operations against `revoke_lineage()` only when all participants share the same database on one host; it is not a distributed or multi-host revocation protocol.
- **CI assurance checks:** Docker image publication now depends on the Python matrix, wheel smoke test, AgentDojo adapter, Ruff/type checks, LangGraph and PostgreSQL checkpoint jobs. The live-model AgentDojo experiment remains credential-gated and is not a required publication dependency. Mypy directly checks a selected set of security-critical modules and their untyped function bodies; this is not package-wide type coverage.
- **Formal and evaluation work:** bounded TLA+ authorization/lifecycle models, deterministic regression tests and a limited AgentDojo adapter are present. The model is not a refinement proof of the Python implementation. The checked-in deterministic simulator is author-written; it is not independent real-agent effectiveness evidence.

The package and workflow changes above do not alter the research maturity claim: PAC++ New remains a prototype with selected in-process reference controls, not a complete or independently certified enforcement system.

The provider connectors remain **reference adapters, not production provider integrations**. Live provider identity/account binding, OAuth refresh-token KMS custody, webhook/deletion propagation, incremental synchronization, provider audit correlation and remote destination-side authorization are outstanding. The project also remains without independent penetration testing, host escape testing for attacker-controlled workers, standard MCP/A2A message interoperability, automated capture of all model-context dependencies, distributed provenance/value stores and destination-side atomic authorization for remote effects.

The task-wide quota in SQLite is single-host. PostgreSQL authority state is shared-primary only; provenance/value stores and the Monitor operation ledger remain separate SQLite components. Direct database access, unwrapped tools, subprocesses and remote resource calls remain explicit bypass boundaries.

Framework interface references used during implementation:
- [LangGraph store base API](https://reference.langchain.com/python/langgraph/store/base/BaseStore), including the required sync/async batch operations and store operation types.
- [LangChain agent middleware](https://docs.langchain.com/oss/python/langchain/agents/middleware), including synchronous and asynchronous tool interception.

The Phase C implementation is deliberately scoped to selected, instrumented lifecycle boundaries. The claim discipline in Section 9 remains in force.
