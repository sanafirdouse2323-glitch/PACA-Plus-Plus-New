# PAC++ New

**Status: security research prototype. Not production-ready.**

PAC++ New explores provenance-aware, capability-based authorization across selected LLM-agent boundaries. It contains a policy monitor, explicit provenance and authority records, durable memory/authority components, framework adapters, read-only provider connectors, a deterministic simulator and bounded TLA+ models.

It does **not** provide complete lifecycle mediation or a universal security boundary for every input, memory, planning, communication, tool or external-effect path. The repository includes a reference orchestration class, but it protects only calls routed through its configured adapters; security also depends on host-supplied identity, provenance and resource controls.

**Repository boundary:** this repository is separate from the [PACA-Plus-Plus enterprise authorization gateway](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus). Do not combine their code, deployment claims or research evidence.

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
| Agent orchestration | `paca/agent_runtime.py` | The reference runtime mediates calls routed through its methods; direct clients and alternate execution paths can bypass it. |
| Provenance and memory | `paca/provenance.py`, `paca/durable.py`, `paca/memory.py` | Memory, connector and message adapters depend on trusted host integrations; not every hidden model-context dependency is tracked automatically. |
| Authority and revocation | `paca/authority_registry.py`, `paca/authority_runtime.py`, `paca/postgres_authority.py` | Registry state and credential issuance are separate modules; PostgreSQL shares authority state across clients on one primary, not every other store. |
| Local resource commits | `paca/resource_commit.py`: opt-in backend-neutral `FencedResourceExecutor` for `write_file` and `mem_write` (with `SQLiteFencedResourceExecutor` retained as a compatibility alias) | SQLite and PostgreSQL fence selected logical resource writes in authority-registry transactions; this is not an actual OS filesystem write or a remote provider commit protocol, and the fence is not enabled for every executor. |
| Framework adapters | `paca/integrations/agentdojo.py`, `paca/integrations/langgraph.py`, `paca/integrations/langchain_middleware.py`, `paca/integrations/langgraph_checkpoint.py` | Direct calls to underlying tools, stores, checkpointers or databases can bypass wrappers. |
| Provider ingress | Read-only Gmail, Microsoft Graph, Slack and Qdrant connectors | CI uses mocked HTTP; production identity binding and live account validation remain deployment work. |
| Process and network helpers | Optional digest-pinned Docker worker; `PACAAgentRuntime(require_docker_sandbox_for_effects=True)` requires the concrete Docker executor for `run_command` effects routed through `execute_effect`/`aexecute_effect` | Strict mode is opt-in and only governs calls through that runtime. It rejects other action types until brokered resource/provider paths exist, but does not stop direct host/framework/subprocess/provider bypasses. It still trusts the Docker CLI/daemon and host kernel and cannot yet be combined with resource-commit-fence mode. |
| Formal models | `models/PACAAuth.tla` and `models/PACALifecycle.tla` | Bounded model checking is not a proof that Python code refines the model. |

## Install optional integrations

Install only the extras needed by the application:

```bash
python -m pip install -e ".[dev,agentdojo]"
python -m pip install -e ".[dev,langgraph]"
python -m pip install -e ".[dev,langgraph-postgres]"
python -m pip install -e ".[providers]"
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

- **Mediation and bypass:** raw filesystem, database, network, subprocess and framework calls can bypass Python adapters. Each protected resource must keep raw credentials and clients away from agent-controlled code and enforce access at the resource boundary.
- **Identity and task binding:** identity and task-context callbacks are trusted host integrations. There is no built-in production OIDC/workload-identity service.
- **Key management:** Ed25519 separates issuer signing from public-key verification, but KMS/HSM custody, key rotation, authenticated key distribution and emergency key revocation are not implemented.
- **State and recovery:** the provenance repository, memory value store and Monitor operation ledger use SQLite. The PostgreSQL authority registry is single-primary; cross-store atomicity, safe failover/rollback detection and full-state replication are not provided.
- **External effects:** provider adapters are read-only. Local resource-commit fencing covers only selected local writes; remote provider-side authorization, idempotency and commit fencing are not implemented.
- **Isolation and approvals:** Docker worker enforcement is opt-in per `PACAAgentRuntime`; strict mode accepts only `run_command` and requires the concrete Docker executor for calls routed through the runtime. It rejects file, memory and provider actions until brokered access paths exist. It is not an OS-level mandatory-access-control boundary and does not stop direct framework, subprocess, host filesystem or provider-client calls. Composition with the filesystem commit fence remains outstanding. A production approval service is not included; approval verification must be supplied by trusted host code.
- **Evaluation:** there is no independent security audit, comprehensive host-level bypass evaluation or completed live-agent effectiveness study.
- **Repository governance:** the last confirmed repository-settings inspection on 24 November 2026 found no active branch-protection ruleset. The current GitHub connection cannot read the branch-protection endpoint (403), so the live setting could not be rechecked in this update. A repository administrator must apply and verify the settings in `docs/REPOSITORY_SECURITY_CONFIGURATION.md`.

Do not deploy PAC++ New as the sole security control protecting company data, accounts or autonomous business operations.

## Documentation map

- [Current implementation status and next gates](docs/security-roadmap.md)
- [Research question, related work and evaluation plan](docs/AGENT_LIFECYCLE_SECURITY_RESEARCH.md)
- [Durable lifecycle implementation and trust boundaries](docs/DURABLE_LIFECYCLE_SECURITY.md)
- [Direct-bypass evaluation](docs/DIRECT_BYPASS_EVALUATION.md)
- [AgentDojo integration](docs/agentdojo-integration.md)
- [Sandbox and external-containment evaluation protocol](docs/CONTAINMENT_EVALUATION.md)
- [PostgreSQL checkpoint adapter](docs/POSTGRES_CHECKPOINT_AND_LIFECYCLE_MODEL.md)
- [Repository protection configuration](docs/REPOSITORY_SECURITY_CONFIGURATION.md)

## Licence

This is a source-available academic and non-commercial project. Commercial use requires separate written permission; see [LICENSE](LICENSE).