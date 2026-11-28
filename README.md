# PAC++ New

**Status: security research prototype. Not production-ready.**

PAC++ New explores provenance-aware, capability-based authorization across selected LLM-agent boundaries. It contains a policy monitor, explicit provenance and authority records, durable memory/authority components, framework adapters, read-only provider connectors, a deterministic simulator and bounded TLA+ models.

It does **not** provide complete lifecycle mediation or a universal security boundary for every input, memory, planning, communication, tool or external-effect path. The repository includes a reference orchestration class, but it protects only calls routed through its configured adapters; security also depends on host-supplied identity, provenance and resource controls.

**Repository boundary:** this repository is separate from the [PACA-Plus-Plus enterprise authorization gateway](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus). Do not combine their code, deployment claims or research evidence.

## Research scope and comparator positioning

**PACA++ New is an AI-agent lifecycle-security research project, not an enterprise security gateway.** Its intended research scope is continuous authorization and usage control across an agent's operational lifecycle: input and retrieval, memory/context, planning, tool invocation, inter-agent communication, delegation, and consequential action execution/commit. This describes the research target, not a claim that every stage is currently mediated by the implementation. The current code protects selected paths routed through configured PACA components; direct framework, host, store, subprocess and provider paths can remain outside the boundary.

The distinction from two important research comparators is about *scope*, not a claim that PACA is already more effective:

| Work | Primary focus | Relationship to PACA++ New |
|---|---|---|
| **Multi-CaMeL — “Can CaMeLs Talk?”** ([paper](https://arxiv.org/abs/2610.05640)) | Preserving trusted-instruction/untrusted-data separation and provenance across communication in hierarchical agent-as-tool systems; addresses cross-agent “boundary laundering”. | A focused mechanism and direct comparator for PACA's inter-agent communication and delegation stages. Its reported results are specific to its evaluated settings and do not establish coverage of the entire agent lifecycle. |
| **AID-Guard — “Stateful Authorization for Delegated Agent Effects”** ([paper](https://arxiv.org/abs/2608.21159)) | Authorization-to-effect closure: commit-time request/provider-state revalidation, reservations, and retry/recovery handling under declared provider contracts. | A focused mechanism and direct comparator for PACA's consequential action/effect stage. It addresses a narrower authorization-to-effect lifecycle, not the full memory/planning/communication lifecycle. |
| **PACA++ New** | A proposed unified lifecycle model spanning memory/context, planning, tool use, communication, delegation and effect execution. | Broader intended lifecycle scope; currently a partial research prototype, not demonstrated complete mediation or a proven superset of the focused guarantees above. |

The key research question is therefore not whether PACA lists more lifecycle stages. It is whether a single, composable model preserves authority and information constraints *between* those stages and provides measurable additional protection beyond focused controls such as Multi-CaMeL and AID-Guard. Those systems should be treated as complementary mechanisms and serious baselines, not dismissed as narrower or weaker implementations. See [the research programme](docs/AGENT_LIFECYCLE_SECURITY_RESEARCH.md) for the comparison and evidence requirements.

## Installation profiles

Three additive dependency profiles are available: **Core** (`.[core]`) for the lightweight authorization/policy/provenance and local-resource reference components; **Extended** (`.[extended]`) for optional PostgreSQL, API, provider-client and framework Python integrations; and **Research** (`.[research]`) for Extended plus AgentDojo and pytest. Docker, PostgreSQL servers, TLA+/TLC, model credentials and secure deployment configuration are **not** installed by pip. The original fine-grained extras remain supported. See [installation profiles and verification gates](docs/INSTALLATION_PROFILES.md).

## Quick start

Requires Python 3.10 or later.

```bash
python -m pip install -e ".[dev,api,providers]"
pytest -q
python -m paca list
python -m paca demo C02 paca
python -m paca bench /tmp/paca-benchmark
```

The benchmark command writes `index.html` and `results.json` into the selected output directory. Use a temporary directory so the checked-in historical report under `docs/` is not overwritten accidentally.

## What is implemented

| Responsibility group | Included modules | Current boundary |
|---|---|---|
| **1. Policy and lifecycle enforcement** | Policy language and evaluation: `paca/ast.py`, `parser.py`, `compiler.py`, `evaluator.py`, `engine.py`, `obligations.py`; enforcement and request flow: `monitor.py`, `runtime.py`, `lifecycle.py`, `agent_runtime.py`; packaged policies | The Monitor evaluates configured rules and capability/effect checks. The lifecycle controller adds session, task, purpose, epoch and selected provenance/tool checks. The agent runtime routes supported calls. These are complementary responsibilities, not duplicate policy engines; only configured PACA paths are covered. |
| **2. Authority and usage state** | `paca/authority.py`, `authority_runtime.py`, `authority_registry.py`, `postgres_authority.py`, `ledger.py` | Capability issuance/verification, delegation, revocation, quotas and selected replay/operation state. The Monitor's operation ledger remains separate from authority-registry quota/revocation state because it records different transitions. PostgreSQL is a shared-primary authority backend, not a unified distributed lifecycle store. Production OIDC/workload identity and KMS/HSM key custody are not implemented. |
| **3. Information provenance and memory** | `paca/provenance.py`, `durable.py`, `memory.py` | Typed labels, lineage, durable provenance metadata, memory values and selected trusted memory/connector/message adapters. Values and provenance metadata use separate stores; trusted host adapters must supply source and lineage evidence. Hidden model-context dependencies and raw-store bypasses remain. |
| **4. Protected-resource mediation and commits** | `paca/resource_commit.py`, `filesystem_commit.py`, `broker.py`, `broker_write.py`, `unix_broker.py`, and `paca/contracts/` | Several intentionally distinct paths: the runtime's logical-resource fence, optional Linux filesystem writer, separate signed local logical-file broker mediators, and optional AF_UNIX transport. They are not one universally wired pipeline. Remote-provider mutations and destination-side commit fencing are not implemented. |
| **5. Execution containment and secure I/O** | `paca/sandbox.py`, `secure_io.py`, `secure_network.py` | Optional digest-pinned Docker command execution and selected Linux filesystem/network protections. These helpers have different scopes; they are not a mandatory OS sandbox and are not automatically applied to every tool or connector. |
| **6. Framework and provider adapters** | `paca/integrations/agentdojo.py`, `langchain_middleware.py`, `langgraph.py`, `langgraph_checkpoint.py`, `providers.py` | Explicitly wired AgentDojo, LangChain and LangGraph paths plus read-only Gmail, Microsoft Graph, Slack and Qdrant ingress. Direct tool/framework/database calls can bypass wrappers; provider CI uses mocked HTTP and does not establish live-account security. |

These are **six responsibility groups**, not six complete or independently deployable security layers. A row groups related modules for clarity; it does not assert that all modules are connected in one execution path.

**Not counted as additional runtime security components:** the simulator, scenario corpus, benchmark runners, statistics helpers, reports, tests and TLA+ models are evaluation/assurance tooling. They provide evidence for selected properties but do not themselves mediate agent effects.

**Why some modules remain separate:** the Monitor operation ledger and authority registry store different security state; the runtime resource fence, broker write mediator and filesystem commit adapter implement different effect paths; and the AF_UNIX transport supplies IPC/peer binding rather than duplicating resource policy. Combining these without a common transaction and trust contract would hide important boundaries.

## Security profile conformance

The `core`, `extended` and `research` installation extras are convenience dependency profiles, not separate authorization implementations. CI installs each profile into a clean environment and runs the same shared security-contract tests (`tests/test_profile_security_contract.py`) for capability authorization/revocation, provenance label and lineage preservation, and request-bound single-use local resource commits. This checks that adding optional dependencies does not change these Core contracts. It does **not** prove that every optional framework/provider adapter is secure or completely mediated; those integrations retain their own tests and documented boundaries.

## Install optional integrations

Install only the extras needed by the application:

```bash
python -m pip install -e ".[dev,agentdojo]"
python -m pip install -e ".[dev,langgraph]"
python -m pip install -e ".[dev,langgraph-postgres]"
python -m pip install -e ".[providers]"
python -m pip install -e ".[protocol]"
python -m pip install -e ".[postgres]"
```

For the AgentDojo adapter, inspect the supported workspace tasks with `paca-agentdojo --list-supported-tasks`. The workspace mapper supports a limited read/search set plus the explicit `get_unread_emails` to `mark_mail_read` state change. It rejects unsupported workspace mutations. This is not a generic agent adapter.

## Local reference API

The FastAPI service is a **decision demonstration only**:

```bash
python -m pip install -e ".[api]"
uvicorn paca_executor:app --host 127.0.0.1 --port 8000
```

`GET /health` and `POST /decide` are available locally. The API accepts caller-supplied demonstration capability data, does not authenticate an issuer or connect to real tools, and always reports `effect_executed: false`. It is not an authorization boundary for real actions. Do not expose it to an untrusted network or treat its response as the sole control protecting a resource.

The Dockerfile builds this same reference API. Binding the host port to `127.0.0.1` is intended for local demonstration, not public service deployment.

## Evidence and evaluation limits

The built-in simulator contains 30 author-written deterministic attack scenarios and 11 benign workflows. Its comparison defences are hand-authored models, not independently deployed products. The scenarios and baselines were developed alongside this code, so the reported scores are preliminary internal simulation results—not independent evidence of real-agent attack resistance.

The latest generated simulator output is attached as the `paca-benchmark-regenerated` artifact to the [main-branch CI runs](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New/actions/workflows/ci.yml?query=branch%3Amain). The checked-in `docs/index.html` and `docs/results.json` are historical snapshots. The credential-dependent live AgentDojo benchmark is skipped when `OPENAI_API_KEY` is unavailable; adapter tests and dry runs are not live effectiveness measurements.

The current simulated PACA++ failures include E02 (agent-message propagation, with five simulated harmful effects), R01 (a harmful action based on an incorrect trusted source) and R02 (misleading content sent to the intended recipient). Provenance establishes recorded origin, not truth or semantic safety.

## Production gaps — read before integrating

- **Lifecycle enforcement:** `LifecycleSecurityController` binds PACA-managed effect requests to one session/task, rejects untrusted or incomplete-lineage consequential inputs, requires digest-pinned tool manifests and provides a one-way stop switch. It is only enforced by calls routed through `PACAAgentRuntime`; it does not mediate direct framework/provider clients, raw stores, subprocesses or network paths. Its `session_id` is local audit context rather than an authenticated request field. Its one-use digest cache is bounded but process-local, not durable or shared across replicas. Generic Python executor callbacks remain trusted host configuration; the manifest digest does not independently authenticate arbitrary callback code.
- **Mediation and bypass:** the optional Linux AF_UNIX broker transport in `paca/unix_broker.py` provides a separate-process path for selected local read/write mediators. It is not universal complete mediation or an OS sandbox. Raw filesystem, database, network, subprocess, framework and provider calls remain possible unless deployment policy removes workers' direct access to protected resources and credentials.
- **Identity and task binding:** identity and task-context callbacks are trusted host integrations. There is no built-in production OIDC/workload-identity service.
- **Key management:** Ed25519 separates issuer signing from public-key verification, but KMS/HSM custody, key rotation, authenticated key distribution and emergency key revocation are not implemented.
- **State and recovery:** the provenance repository, memory value store and Monitor operation ledger use SQLite. The PostgreSQL authority registry is single-primary; cross-store atomicity, safe failover/rollback detection and full-state replication are not provided.
- **External effects:** provider adapters are read-only. The optional Linux/local-filesystem writer covers only `write_file`; the library adapter does not spawn the broker process. The AF_UNIX transport can dispatch the existing local mediators when explicitly configured, but it does not automatically broker all reads/writes or prevent direct host/framework access. All filesystem broker writers for one root must share one private recovery-state directory. Gmail, Graph, Slack, Qdrant and other remote provider mutations still have no destination-side authorization, conditional commit or idempotency integration.
- **Isolation and approvals:** Docker worker enforcement is opt-in per `PACAAgentRuntime`; strict mode accepts only `run_command` and requires the concrete Docker executor for calls routed through the runtime. It rejects file, memory and provider actions until brokered access paths exist. It is not an OS-level mandatory-access-control boundary and does not stop direct framework, subprocess, host filesystem or provider-client calls. Composition with the filesystem commit fence remains outstanding. A production approval service is not included; approval verification must be supplied by trusted host code.
- **Evaluation:** the pinned Ratchet core tests and published paper-number reproduction script have been reproduced in CI and retained as baseline evidence. This is not a matched PACA-versus-Ratchet live-agent experiment. There is still no independent security audit, comprehensive host-level bypass evaluation or completed live-agent effectiveness study; the credential-dependent AgentDojo model run requires a protected `OPENAI_API_KEY`.
- **Repository governance:** rechecked on 28 November 2026: GitHub still reports `main` as unprotected (`protected: false`), and the repository rulesets endpoint is empty. This connection can inspect the state but does not expose a supported repository-administration write action. A repository administrator must apply and verify the settings in `docs/REPOSITORY_SECURITY_CONFIGURATION.md`.

Do not deploy PAC++ New as the sole security control protecting company data, accounts or autonomous business operations.

## Documentation map

- [Open, platform-independent architecture specification](docs/ARCHITECTURE_SPECIFICATION.md) — proposed target architecture (Draft v0.2.0; not an implementation or security guarantee).
- [Protocol SDK and conformance tests](paca/contracts/) — canonical JSON, domain-separated digests and structural validation helpers.
- [Versioned protocol contracts v1.0.0](contracts/v1.0.0/README.md) — JSON Schemas and message-security semantics.
- [Security semantics](docs/SECURITY_SEMANTICS.md) — delegation, provenance, revocation and commit state rules.
- [Agent-lifecycle enforcement](docs/AGENT_LIFECYCLE_ENFORCEMENT.md) — fail-closed session, provenance, tool and commit checks for the PACA-owned runtime boundary.
- [Current implementation status and next gates](docs/security-roadmap.md)
- [Lifecycle Phase A baseline audit and threat model](docs/LIFECYCLE_PHASE_A_BASELINE_AUDIT.md)
- [Research question, related work and evaluation plan](docs/AGENT_LIFECYCLE_SECURITY_RESEARCH.md)
- [Durable lifecycle implementation and trust boundaries](docs/DURABLE_LIFECYCLE_SECURITY.md)
- [Direct-bypass evaluation](docs/DIRECT_BYPASS_EVALUATION.md)
- [AgentDojo integration](docs/agentdojo-integration.md)
- [Sandbox and external-containment evaluation protocol](docs/CONTAINMENT_EVALUATION.md)
- [PostgreSQL checkpoint adapter](docs/POSTGRES_CHECKPOINT_AND_LIFECYCLE_MODEL.md)
- [Repository protection configuration](docs/REPOSITORY_SECURITY_CONFIGURATION.md)
- [Linux separate-process broker transport and deployment boundary](docs/UNIX_BROKER_DEPLOYMENT.md)
- [Seven security requirements: implementation and evidence status](docs/SEVEN_REQUIREMENTS_STATUS.md)
- [Core, Extended and Research installation profiles](docs/INSTALLATION_PROFILES.md)

## Licence

This is a source-available academic and non-commercial project. Commercial use requires separate written permission; see [LICENSE](LICENSE).