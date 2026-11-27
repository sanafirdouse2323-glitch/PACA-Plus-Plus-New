# Installation profiles — PACA-Plus-Plus-New

These are **dependency profiles**, not three different security products or certification levels. Each higher profile includes the Python requirements of the preceding profile. Installing a profile does not automatically start, configure, authenticate or secure any external service.

| Profile | Install | What it enables | What it does not imply |
| --- | --- | --- | --- |
| **Core** | `python -m pip install -e ".[core]"` | Base authorization, policy, provenance, memory and selected local-resource reference components | No complete mediation; optional cryptographic/protocol paths still require their documented dependencies |
| **Extended** | `python -m pip install -e ".[extended]"` | Core plus Python dependencies for PostgreSQL, API, HTTP provider clients, LangGraph/LangChain and checkpoint integrations | Does not install or start PostgreSQL or Docker; does not configure credentials or enforce host isolation |
| **Research** | `python -m pip install -e ".[research]"` | Extended plus pinned AgentDojo and pytest for experiments and benchmarking | Does not supply a live-model API key, run benchmarks, install TLC/TLA+ or prove security |

## Reproducible setup

Use a fresh virtual environment for **one** chosen profile:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[core]"
python -m paca list
python -m paca demo C02 paca
```

For Extended, replace the final install command with `python -m pip install -e ".[extended]"`. For Research, use `python -m pip install -e ".[research]"`. On Windows, use the platform's virtual-environment activation command; Linux-only broker and filesystem protections are not portable to Windows.

The old granular extras (`crypto`, `protocol`, `postgres`, `providers`, `api`, `agentdojo`, `langgraph`, `langgraph-postgres`, `dev`) remain available. If a Core-only workflow needs Ed25519 signing or canonical JSON/schema validation, explicitly install `.[crypto]` or `.[protocol]`; the zero-dependency base is not a claim that every optional path works without these libraries.

## External prerequisites and security boundaries

- **PostgreSQL** is a separately provisioned database, not installed by pip. A single-primary authority registry is not multi-primary distributed consensus or cross-store atomicity.
- **Docker** is an external daemon/CLI and deployment trust boundary, not a Python package in these extras. Worker isolation is opt-in and must be tested against direct bypass paths.
- **Linux AF_UNIX broker** requires suitable OS users, permissions and peer-credential support; installing Extended does not launch or connect a broker.
- **FastAPI** provides a decision demonstration, not an authenticated production authorization gateway.
- **AgentDojo** adapter tests and dry runs do not establish live-agent attack resistance. Live experiments need a separately configured protected model credential and pre-registered matched baselines.
- **TLA+/TLC** and any required Java runtime must be installed separately for formal model checking. Bounded TLC model checking does not prove deployed Python code secure.
- **Production credentials, KMS/HSM, workload identity, provider commit fencing, independent audit and complete mediation** are not supplied by any profile.

## Verification gates

1. **Core:** clean-environment install, import and CLI smoke test; run selected core tests with pytest installed separately; verify policy decisions and fail-closed behavior.
2. **Extended:** clean-environment install and import checks; run PostgreSQL integration against a real isolated database, framework adapter tests, API smoke tests and Docker/broker integration on supported hosts. Verify unmediated access denial separately.
3. **Research:** run reproducible simulator and AgentDojo adapter tests; run bounded live experiments only when credentials are available; execute TLC separately; retain raw traces, baseline configurations, attack success, utility, latency and costs.

Do not describe a passing install, adapter smoke test or model-checking run as proof of complete security. See [seven security requirements](SEVEN_REQUIREMENTS_STATUS.md).
