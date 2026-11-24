# PAC++ New

**Status: security research prototype. Not production-ready.**

PAC++ New explores provenance-aware, capability-based authorization across selected LLM-agent boundaries. It contains a policy monitor, explicit provenance and authority records, durable memory/authority components, framework adapters, read-only provider connectors, a deterministic simulator and bounded TLA+ models.

It does **not** provide a complete agent runtime or mediate every input, memory, planning, communication, tool or external-effect path. Security applies only where an integration actually routes the operation through PACA and where the host supplies trustworthy identity, provenance and resource adapters.

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
| Provenance and memory | `paca/provenance.py`, `paca/durable.py`, `paca/memory.py` | Labels and lineage depend on trusted connectors; not every hidden model-context dependency is tracked automatically. |
| Authority and revocation | `paca/authority_runtime.py`, `paca/postgres_authority.py` | PostgreSQL shares authority state across clients on one primary; it does not make every other store distributed. |
| Local resource commits | Opt-in `SQLiteFencedResourceExecutor` for `write_file` and `mem_write` | Not a remote provider commit protocol and not enabled for every executor. |
| Framework adapters | AgentDojo, LangGraph store, LangChain middleware and PostgreSQL checkpoint adapters | Direct calls to underlying tools, stores or databases can bypass wrappers. |
| Provider ingress | Read-only Gmail, Microsoft Graph, Slack and Qdrant connectors | CI uses mocked HTTP; production identity binding and live account validation remain deployment work. |
| Process and network helpers | Optional Docker worker plus Linux filesystem/network primitives | The isolated worker is opt-in; helpers are not wired into every path. |
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
- **Isolation and approvals:** Docker worker isolation is optional, not mandatory for every executor. A production approval service is not included; approval verification must be supplied by trusted host code.
- **Evaluation:** there is no independent security audit, comprehensive host-level bypass evaluation or completed live-agent effectiveness study.
- **Repository governance:** `main` currently has no active branch-protection ruleset or required review/check policy. A repository administrator must apply and verify the settings in `docs/REPOSITORY_SECURITY_CONFIGURATION.md`.

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