# PAC++ New

**Status: security research prototype. Not production-ready.**

PAC++ New explores provenance-aware, capability-based authorization across selected LLM-agent boundaries. It contains a policy monitor, explicit provenance and authority records, durable memory/authority components, framework adapters, read-only provider connectors, a deterministic simulator and bounded TLA+ models.

It does **not** provide complete lifecycle mediation or a universal security boundary for every input, memory, planning, communication, tool or external-effect path. The repository includes a reference orchestration class, but it protects only calls routed through its configured adapters; security also depends on host-supplied identity, provenance and resource controls.

**Repository boundary:** this repository is separate from the [PACA-Plus-Plus enterprise authorization gateway](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus). Do not combine their code, deployment claims or research evidence.

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

| Area | Implemented reference components | Important boundary |
|---|---|---|
| Policy enforcement | `paca/monitor.py`, `paca/runtime.py`, packaged PACA policy | Covers selected, explicitly mapped actions; it is not a universal framework hook. |
| Lifecycle security | `paca/lifecycle.py` and optional `PACAAgentRuntime(lifecycle_security=...)` | Session/task binding, fail-closed provenance/tool checks, one-use lifecycle commits and a kill switch for calls through the reference runtime; direct clients and external resources remain outside this boundary. |
| Policy continuity | `docs/POLICY_CONTINUITY_EVALUATION.md` | Defines measurable authority, information, usage and effect continuity invariants across transformation, delegation, retry, revocation and external-sink tests; it is an evaluation contract, not proof of complete mediation. |
| Agent orchestration | `paca/agent_runtime.py` | The reference runtime mediates calls routed through its methods; direct clients and alternate execution paths can bypass it. |
| Provenance and memory | `paca/provenance.py`, `paca/durable.py`, `paca/memory.py` | Memory, connector and message adapters depend on trusted host integrations; not every hidden model-context dependency is tracked automatically. |
| Authority and revocation | `paca/authority_registry.py`, `paca/authority_runtime.py`, `paca/postgres_authority.py` | Registry state and credential issuance are separate modules; PostgreSQL shares authority state across clients on one primary, not every other store. |
| Resource commits | `paca/resource_commit.py`: logical `FencedResourceExecutor` for `write_file` and `mem_write`; `paca/filesystem_commit.py`: opt-in Linux `FilesystemFencedResourceExecutor` for real `write_file` replacement with a durable recovery journal | Strict runtime mode accepts only the exact built-in logical or filesystem executor type, bound to the runtime's authority and registry; the filesystem adapter seals its configuration after initialization. Logical values and filesystem recovery sidecar state use separate registry key namespaces, and immutable committed-version evidence supports filesystem journal recovery. These are selected resource controls, not an OS isolation boundary. The filesystem adapter remains write-only and Linux/local-filesystem-specific; it requires a private broker-owned root, one shared private state directory per root, existing parent directories and openat2. The optional `paca/unix_broker.py` transport can run the existing local read/write mediators in a separate Linux process, but the filesystem adapter does not spawn or configure that process. Neither path automatically covers every executor or fences remote providers. |
| v1.0.0 broker reference path | `paca/contracts/broker.py`, `paca/contracts/permits.py`, `paca/broker.py`, `paca/broker_write.py`; optional Linux process transport in `paca/unix_broker.py` | The original mediators provide bounded local reads and signed local logical-file writes through the authority registry; protocol commit permits are verified and consumed transactionally under schema v7. The optional AF_UNIX adapter authenticates local peer UIDs/GIDs with `SO_PEERCRED` in both directions and dispatches one signed read/write operation per connection. It is not enabled or wired into every runtime by default, does not enforce OS access restrictions, and does not provide remote network mediation, provider mutations or complete resource mediation. |
| Framework adapters | `paca/integrations/agentdojo.py`, `paca/integrations/langgraph.py`, `paca/integrations/langchain_middleware.py`, `paca/integrations/langgraph_checkpoint.py` | Direct calls to underlying tools, stores, checkpointers or databases can bypass wrappers. |
| Provider ingress | Read-only Gmail, Microsoft Graph, Slack and Qdrant connectors | CI uses mocked HTTP; production identity binding and live account validation remain deployment work. |
| Process and network helpers | Optional digest-pinned Docker worker; `PACAAgentRuntime(require_docker_sandbox_for_effects=True)` requires the concrete Docker executor for `run_command` effects routed through `execute_effect`/`aexecute_effect` | Strict mode is opt-in and only governs calls through that runtime. It rejects other action types until brokered resource/provider paths exist, but does not stop direct host/framework/subprocess/provider bypasses. It still trusts the Docker CLI/daemon and host kernel and cannot yet be combined with resource-commit-fence mode. |
| Formal models | Bounded TLA+ models for authorization, lifecycle, broker operations, grant attenuation and information flow/declassification | TLC checks only the finite configurations in the model files; it does not prove Python refinement, deployed database behavior or production security. |

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

- **Lifecycle enforcement:** `LifecycleSecurityController` binds PACA-managed effect requests to one session/task, rejects untrusted or incomplete-lineage consequential inputs, requires digest-pinned tool manifests and provides a one-way stop switch. It is only enforced by calls routed through `PACAAgentRuntime`; it does not mediate direct framework/provider clients, raw stores, subprocesses or network paths. Its one-use digest cache is bounded but process-local, not durable or shared across replicas. Generic Python executor callbacks remain trusted host configuration; the manifest digest does not independently authenticate arbitrary callback code.
- **Mediation and bypass:** the optional Linux AF_UNIX broker transport in `paca/unix_broker.py` provides a separate-process path for selected local read/write mediators. It is not universal complete mediation or an OS sandbox. Raw filesystem, database, network, subprocess, framework and provider calls remain possible unless deployment policy removes workers' direct access to protected resources and credentials.
- **Identity and task binding:** identity and task-context callbacks are trusted host integrations. There is no built-in production OIDC/workload-identity service.
- **Key management:** Ed25519 separates issuer signing from public-key verification, but KMS/HSM custody, key rotation, authenticated key distribution and emergency key revocation are not implemented.
- **State and recovery:** the provenance repository, memory value store and Monitor operation ledger use SQLite. The PostgreSQL authority registry is single-primary; cross-store atomicity, safe failover/rollback detection and full-state replication are not provided.
- **External effects:** provider adapters are read-only. The optional Linux/local-filesystem writer covers only `write_file`; the library adapter does not spawn the broker process. The AF_UNIX transport can dispatch the existing local mediators when explicitly configured, but it does not automatically broker all reads/writes or prevent direct host/framework access. All filesystem broker writers for one root must share one private recovery-state directory. Gmail, Graph, Slack, Qdrant and other remote provider mutations still have no destination-side authorization, conditional commit or idempotency integration.
- **Isolation and approvals:** Docker worker enforcement is opt-in per `PACAAgentRuntime`; strict mode accepts only `run_command` and requires the concrete Docker executor for calls routed through the runtime. It rejects file, memory and provider actions until brokered access paths exist. It is not an OS-level mandatory-access-control boundary and does not stop direct framework, subprocess, host filesystem or provider-client calls. Composition with the filesystem commit fence remains outstanding. A production approval service is not included; approval verification must be supplied by trusted host code.
- **Evaluation:** the pinned Ratchet core tests and published paper-number reproduction script have been reproduced in CI and retained as baseline evidence. This is not a matched PACA-versus-Ratchet live-agent experiment. There is still no independent security audit, comprehensive host-level bypass evaluation or completed live-agent effectiveness study; the credential-dependent AgentDojo model run requires a protected `OPENAI_API_KEY`.
- **Repository governance:** rechecked on 26 November 2026 after the security merges: GitHub still reports `main` as unprotected (`protected: false`), and the repository rulesets endpoint is empty. This connection can inspect the state but does not expose a supported repository-administration write action. A repository administrator must apply and verify the settings in `docs/REPOSITORY_SECURITY_CONFIGURATION.md`.

Do not deploy PAC++ New as the sole security control protecting company data, accounts or autonomous business operations.

## Documentation map

- [Open, platform-independent architecture specification](docs/ARCHITECTURE_SPECIFICATION.md) — proposed target architecture (Draft v0.2.0; not an implementation or security guarantee).
- [Protocol SDK and conformance tests](paca/contracts/) — canonical JSON, domain-separated digests and structural validation helpers.
- [Versioned protocol contracts v1.0.0](contracts/v1.0.0/README.md) — JSON Schemas and message-security semantics.
- [Security semantics](docs/SECURITY_SEMANTICS.md) — delegation, provenance, revocation and commit state rules.
- [Agent-lifecycle enforcement](docs/AGENT_LIFECYCLE_ENFORCEMENT.md) — fail-closed session, provenance, tool and commit checks for the PACA-owned runtime boundary.
- [Current implementation status and next gates](docs/security-roadmap.md)
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