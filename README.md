# PACA++ New

**Status: security research prototype. Not production-ready.**

PACA++ New investigates provenance-aware, capability-based authorisation across selected LLM-agent lifecycle boundaries. The repository contains policy and lifecycle controls, authority and provenance components, local resource mediators, optional execution controls, framework adapters, read-only provider integrations, evaluation tooling and bounded TLA+ models.

It does **not** provide complete lifecycle mediation or a universal security boundary. Only operations routed through configured PACA adapters receive the corresponding checks. Direct host, framework, store, subprocess, network and provider paths can remain outside those boundaries. Do not deploy this project as the sole control protecting sensitive data or consequential actions.

**Repository boundary:** this research project is separate from the [PACA-Plus-Plus enterprise authorisation gateway](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus). Their code, deployment claims and evidence must not be combined.

## Research question

The project studies whether authority and information-provenance constraints can remain consistent as an agent moves through input/retrieval, memory, planning, tools, inter-agent communication, delegation and consequential effects.

The lifecycle is the **research target**, not a claim that every stage is implemented or mediated. The research question is whether a composable model provides measurable protection across transitions beyond focused controls such as [Multi-CaMeL](https://arxiv.org/abs/2610.05640) for cross-agent provenance and [AID-Guard](https://arxiv.org/abs/2608.21159) for delegated effects. PACA++ New has not demonstrated superiority over these systems or a complete lifecycle guarantee. See the [research programme](docs/AGENT_LIFECYCLE_SECURITY_RESEARCH.md).

## Quick start

Requires Python 3.10 or later.

```bash
python -m pip install -e ".[dev,api,providers]"
pytest -q
python -m paca list
python -m paca demo C02 paca
python -m paca bench /tmp/paca-benchmark
```

The benchmark command writes `index.html` and `results.json` to the chosen output directory. Use a temporary directory; the checked-in files under `docs/` are historical report snapshots.

### Offline lifecycle example

```bash
python -m pip install -e ".[dev]"
python examples/lifecycle_security_demo.py --output /tmp/paca-lifecycle-demo.json
```

This deterministic, local SQLite example runs one trusted and one untrusted source through selected retrieval, delegation, messaging and resource-write paths. It uses fixed test data, demonstration HMAC keys and a permissive test metadata callback. It does not call an LLM or external provider and is not a deployment recipe. See [the communication integration notes](docs/LIFECYCLE_COMMUNICATION_INTEGRATION.md).

## Implementation map

The six groups below organise related code; they are **not six complete or independently deployable security layers**.

| Group | Main modules | Implemented scope and boundary |
|---|---|---|
| **1. Policy and lifecycle** | `paca/ast.py`, `parser.py`, `compiler.py`, `evaluator.py`, `engine.py`, `obligations.py`, `monitor.py`, `runtime.py`, `lifecycle.py`, `agent_runtime.py` | Policy evaluation and selected session, task, purpose, policy-epoch, provenance and tool checks. When configured, `PACAAgentRuntime` also checks delegation and message send/receive. Other call paths are not intercepted. |
| **2. Authority and usage state** | `paca/authority.py`, `authority_runtime.py`, `authority_registry.py`, `postgres_authority.py`, `ledger.py` | Capability issuance/verification, delegation, revocation, quotas and operation state. PostgreSQL is a shared-primary authority backend, not a distributed lifecycle store. Production workload identity and managed key custody are not included. |
| **3. Provenance and memory** | `paca/provenance.py`, `durable.py`, `memory.py`, `messages.py` | Typed labels, lineage, durable provenance metadata, memory values and selected memory, connector and message adapters. Values and provenance metadata are stored separately; host adapters must provide trustworthy source and lineage evidence. |
| **4. Resource mediation and commits** | `paca/resource_commit.py`, `filesystem_commit.py`, `broker.py`, `broker_write.py`, `unix_broker.py`, `paca/contracts/` | Distinct logical-resource, filesystem, broker read/write and optional Linux AF_UNIX paths. They are not one universally wired pipeline; remote-provider mutations and universal destination-side commit fencing are absent. |
| **5. Execution and secure I/O** | `paca/sandbox.py`, `secure_io.py`, `secure_network.py` | Optional Docker command execution and selected Linux filesystem/network protections. These are not mandatory OS-wide isolation and are not automatically applied to every tool or connector. |
| **6. Framework and provider adapters** | `paca/integrations/agentdojo.py`, `langchain_middleware.py`, `langgraph.py`, `langgraph_checkpoint.py`, `providers.py` | Explicit AgentDojo, LangChain and LangGraph integrations and read-only Gmail, Microsoft Graph, Slack and Qdrant ingress. Direct framework/tool/database calls can bypass wrappers; provider CI uses mocked HTTP. |

### Why related components remain separate

Some similarly named or adjacent modules enforce different invariants and must not be merged just to reduce file count:

- The **Monitor operation ledger** records monitor operation/token history; the **authority registry** stores capability, revocation, quota and resource-receipt state.
- The **runtime logical-resource fence**, **broker write mediator** and **filesystem commit adapter** have different effect and transaction contracts.
- The **AF_UNIX transport** provides process communication and peer-credential checks for configured mediators; it is not another policy engine or a universal broker.

Tests, TLA+ models, simulators, scenarios, benchmarks and reports are assurance/evaluation tooling, not additional runtime security components.

## Installation profiles and optional integrations

The `core`, `extended` and `research` extras are dependency profiles, not security levels. CI runs the same `tests/test_profile_security_contract.py` contracts under each profile; this checks selected shared behaviour, not complete adapter security.

```bash
python -m pip install -e ".[core]"
python -m pip install -e ".[extended]"
python -m pip install -e ".[research]"
```

The existing fine-grained extras remain available:

```bash
python -m pip install -e ".[dev,agentdojo]"
python -m pip install -e ".[dev,langgraph]"
python -m pip install -e ".[dev,langgraph-postgres]"
python -m pip install -e ".[providers]"
python -m pip install -e ".[protocol]"
python -m pip install -e ".[postgres]"
```

Docker, PostgreSQL servers, TLA+/TLC, model credentials, production identity services and secure deployment configuration must be provisioned separately. See [installation profiles](docs/INSTALLATION_PROFILES.md).

## Local reference API

The FastAPI service is a **decision demonstration only**:

```bash
python -m pip install -e ".[api]"
uvicorn paca_executor:app --host 127.0.0.1 --port 8000
```

`GET /health` and `POST /decide` are available locally. The API accepts caller-supplied demonstration capability data, does not authenticate an issuer or connect to real tools, and always reports `effect_executed: false`. It is not an enforcement boundary for real actions. The Dockerfile builds this same API; do not expose it as a production service.

## Evidence and known limits

The built-in simulator has 30 author-written deterministic attack scenarios and 11 benign workflows. Its comparison defences are hand-authored models, not independently deployed products. Results are internal development evidence, not an independent benchmark or proof of real-agent attack resistance.

The checked-in `docs/index.html` and `docs/results.json` are historical snapshots. CI regenerates simulator output as an artifact. AgentDojo adapter tests and dry-run preflight do not count as live-agent evaluation. The billable live-model benchmark runs only for a pull request explicitly labelled `run-live-agentdojo` and only when the protected `OPENAI_API_KEY` secret is configured. Ordinary branch pushes do not run the live benchmark.

Important unresolved boundaries include:

- **Complete mediation:** raw host, framework, store, database, subprocess and network paths can bypass PACA adapters. The optional AF_UNIX broker is wired only for selected local mediators.
- **Lifecycle context:** the runtime session identifier is local audit context, not authenticated transport identity. Identity/task callbacks and connector labels are trusted host inputs; arbitrary model-context dependencies are not discovered automatically.
- **Keys and identity:** Ed25519 issuer/verifier separation exists, but OIDC/workload identity, KMS/HSM custody, authenticated key distribution, automated rotation and emergency key revocation do not.
- **Persistence and recovery:** provenance, memory values and the Monitor operation ledger use SQLite; the PostgreSQL authority registry is single-primary. Cross-store atomicity, complete replication and safe distributed failover are not provided.
- **External effects and isolation:** provider integrations are read-only. Remote-provider conditional commit/idempotency enforcement and a production approval service are absent. Docker isolation is opt-in and cannot prevent direct host/framework bypasses.
- **Evaluation:** no completed matched live-agent effectiveness study, comprehensive host-level bypass evaluation or independent security audit is claimed.
- **Repository governance:** as rechecked on 29 November 2026, `main` is unprotected and no active repository rulesets were returned. An administrator must configure and verify branch/tag rulesets and required reviewers before setting `PACA_RELEASE_GOVERNANCE_VERIFIED=true`.

CI success and bounded TLC model checks establish results only for the tests and finite states actually exercised. They are not a security certification. See the [seven-requirements status](docs/SEVEN_REQUIREMENTS_STATUS.md), [direct-bypass evaluation](docs/DIRECT_BYPASS_EVALUATION.md) and [repository security configuration](docs/REPOSITORY_SECURITY_CONFIGURATION.md).

## Documentation index

Use each document for one primary purpose:

- **Current implementation and next work:** [security roadmap](docs/security-roadmap.md) (implementation snapshot); [seven requirements](docs/SEVEN_REQUIREMENTS_STATUS.md) (requirement-by-requirement evidence).
- **Research:** [research programme](docs/AGENT_LIFECYCLE_SECURITY_RESEARCH.md) (question and related work); [prototype dossier](docs/RESEARCH_PROTOTYPE_DOSSIER.md) (PhD-facing synthesis); [six-point evaluation protocol](docs/SIX_POINT_INDUSTRY_EVALUATION_PROTOCOL.md) (study design).
- **Target design and semantics:** [architecture specification](docs/ARCHITECTURE_SPECIFICATION.md) (proposed architecture only); [security semantics](docs/SECURITY_SEMANTICS.md); [versioned protocol contracts](contracts/v1.0.0/README.md).
- **Implemented boundaries:** [lifecycle enforcement](docs/AGENT_LIFECYCLE_ENFORCEMENT.md); [durable lifecycle](docs/DURABLE_LIFECYCLE_SECURITY.md); [communication integration](docs/LIFECYCLE_COMMUNICATION_INTEGRATION.md); [AgentDojo](docs/agentdojo-integration.md); [PostgreSQL checkpoint adapter](docs/POSTGRES_CHECKPOINT_AND_LIFECYCLE_MODEL.md); [Linux broker deployment](docs/UNIX_BROKER_DEPLOYMENT.md).
- **Evaluations and historical records:** [Phase A baseline audit](docs/LIFECYCLE_PHASE_A_BASELINE_AUDIT.md) and [Phase 1 adversarial audit](docs/ADVERSARIAL_SECURITY_AUDIT_PHASE_1.md) are historical snapshots, not current full-repository audits; [containment evaluation](docs/CONTAINMENT_EVALUATION.md); [policy continuity](docs/POLICY_CONTINUITY_EVALUATION.md).
- **Repository operations:** [security configuration](docs/REPOSITORY_SECURITY_CONFIGURATION.md); [security reporting policy](SECURITY.md); [changelog](CHANGELOG.md).

## Licence

This is source-available academic and non-commercial software. Commercial use requires separate written permission; see [LICENSE](LICENSE).
