# PACA++ - Provenance-Anchored Continuous Authorization for LLM agents

A small, dependency-free reference monitor that evaluates selected simulated stage-boundary
operations (memory read/write, delegation, tool invocation and egress) to decide whether an *effect* is authorised,
using **provenance labels** instead of trusting anything the model says.

> The path that matters is *untrusted content -> model interpretation -> access to data, tools or an
> external recipient*. PACA++ does not try to stop the model reading malicious text; it stops that
> chain from ending in an unauthorised effect.

```bash
pip install -e .[dev]
pytest -q                       # regression tests
python -m paca bench docs       # runs the benchmark, writes docs/index.html + docs/results.json
python -m paca demo C02 paca    # step-by-step trace of one scenario
python -m paca list
```
Open `docs/index.html` for the checked-in historical interactive report (also deployable on GitHub Pages: Settings -> Pages -> `/docs`). Its embedded scores and traces are not the latest benchmark output. Regenerate it locally with `python -m paca bench docs`, or use the `paca-benchmark-regenerated` artifact attached to the latest successful CI run.

## What it does

| Mechanism | Where | Risk classes exercised in the simulator |
|---|---|---|
| Task-bound, target-bound, expiring **capabilities** (default deny) | `runtime.py`, `monitor.py` C1/C2 | stale authority, goal hijack, cross-stage drift, cost DoS |
| **Provenance labels** that only get worse when data is combined (integrity, sensitivity, tenant, origins); unlabelled `Arg` values default to untrusted | `provenance.py` | provenance laundering, fragmentation, memory poisoning |
| Policy rules in the PACA DSL over those labels (packaged default: `paca/policies/agent_policy.paca`; identical example copy: `examples/agent_policy.paca`) | `engine.py`, `monitor.py` | indirect injection, exfiltration, confused deputy, SSRF, config tampering |
| **Manifest pinning** (hash+version of each tool authorised for the task) | C3 | MCP poisoning/rug-pull, tool-selection hijack, supply chain |
| **Delegation attenuation**, fan-out limit, quarantine after repeated denials | C8/C11/C12 | multi-agent escalation, worms, approval fatigue |
| **Effect tokens**: HMAC over the exact action+args, verified by the executor; approvals bound to the same digest | C13 | planner/critic swap, TOCTOU, replayed approvals |
| Hash-chained **audit log** | `monitor.AuditLog` | forensics / tamper evidence |

## Benchmark (read this before quoting any number)

`paca/scenarios.py` defines **30 author-written deterministic attack simulations**, including
two author-designated residual cases (`R01` and `R02`), plus **11 benign workflows**. The
scenarios are not derived from or validated against a complete external attack catalogue.
Bracketed source keys are provisional research notes, not verified citations. Threat model:
the simulated model is **fully hijacked** by any injected content it reads, so a defence succeeds
only when it blocks the terminal effect. Five hand-authored comparison defences run on the
same scenarios; a "vigilant" human rejects attacker prompts, while a "rubber-stamp" human
approves all prompts.

| Defence | Overall ASR (vigilant) | Overall ASR (rubber-stamp) | In-scope ASR (vigilant) | In-scope ASR (rubber-stamp) | Benign tasks completed | Prompts / benign task |
|---|---:|---:|---:|---:|---:|---:|
| No guard | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.00 |
| Prompt filter | 96.7% | 96.7% | 96.4% | 96.4% | 90.9% (1 false block) | 0.00 |
| Role-based allow-list | 96.7% | 96.7% | 96.4% | 96.4% | 100.0% | 0.00 |
| Sandbox + scoped permissions | 80.0% | 93.3% | 78.6% | 92.9% | 100.0% | 0.27 |
| **PACA++ v0.3** | **10.0%** | **10.0%** | **3.6%** | **3.6%** | **100.0%** | **0.18** |

ASR is the percentage of attack scenarios in which at least one simulated attacker effect executes; lower is better. Overall ASR includes all 30 attack scenarios. In-scope ASR excludes the two author-designated
residual scenarios, leaving 28. In the regenerated PACA++ results, the in-scope success is
`E02` (five simulated attacker effects before containment); the two residual successes are
`R01` and `R02` (one effect each). These are results of this deterministic simulation, not
real-agent experiments or production security measurements. CI uploads the regenerated
interactive report and JSON output as a workflow artifact; it does not automatically overwrite
the checked-in `docs/` snapshot. Run `python -m paca bench docs` to regenerate that local snapshot.

**Limits of this evidence - important:**
- This is a *simulation authored alongside the defence*. The scenario workflows and baselines
  (`baselines.py`) are explicit, hand-authored models of selected control classes, not tests
  of real products or an independent benchmark suite.
- High scores on a defence's own suite are expected; useful outputs include the **ablation**
  (which check uniquely stops which attack), residual cases, benign completion, and false blocks.
- This repository includes an optional AgentDojo ToolsExecutor adapter, a task-scoped
  mapper for 14 workspace read/search operations, and a paired benchmark runner. The runner
  derives exact action/target grants from each selected user's clean AgentDojo ground-truth
  calls, and applies conservative untrusted/max-sensitivity fixture labels. The mapper denies
  unsupported write, delete, send, share, and calendar-mutation tools. This is a limited
  workspace experiment, not a full-suite policy or a completed independent benchmark result.

Explicit non-goals for this prototype: direct jailbreaks, system-prompt extraction, adversarial suffixes,
weight backdoors / training poisoning, membership inference, model extraction, AI-enabled phishing/deepfakes.

## Using the monitor

```python
from paca.monitor import Monitor
from paca.runtime import Capability, Request
from paca.provenance import Arg, Label, derive

m = Monitor()                                   # loads packaged paca/policies/agent_policy.paca
cap = Capability("c1", "sana", "acme", "task1", "assistant",
                 grants={"send_email": ("bob@corp.example",)}, expires=30)
doc = Arg("Q3 numbers", Label("trusted", 3, "acme"))            # label comes from YOUR connector
user_recipient = Arg("bob@corp.example", Label("trusted", origins=frozenset({"user"})))
req = Request("send_email", {"to": user_recipient, "body": derive("summary", doc)}, cap, step=1)
d = m.decide(req)                               # allow | needs_approval | deny (+ reasons, token)
assert m.verify(req, d)                         # executor must verify before acting
```
Integration contract: **labels are assigned by your connectors/memory store, never by the model.**
If an agent framework lets the model attach its own labels, the guarantees do not hold.

**Execution and approval boundaries:** this repository contains an in-process reference monitor
and a deterministic simulator. An optional AgentDojo ToolsExecutor adapter inserts
the monitor before AgentDojo function dispatch. The companion workspace mapper supports
a limited read/search tool set and requires task-specific capabilities and trusted
resource labels. The `paca-agentdojo` runner derives those capabilities from the selected
AgentDojo user task's clean ground-truth calls and conservatively labels fixture data as
untrusted at maximum sensitivity. It deliberately denies mutating workspace tools that
do not yet have dedicated PACA++ action mappings. It is not a generic agent adapter and
does not provide an independent production executor. The scenario harness supplies read
content to `Session.ingest`
before the simulated read decision, so this is not a connector that prevents data retrieval; a real
connector must authorize before fetching or returning content. In this request model, `fetch_url`
treats its declared `query` field as outbound data; implicit HTTP headers, cookies, credentials,
and other transport-layer state are not modeled. A real connector must include any such data in
the authorization-bound request representation. The simulator's memory-read path
authorizes using a separately stored label before looking up the stored value, but it is still an
in-memory test harness, not an integrated memory-store adapter. Inbound communication through
`Session.receive` and agent planning are not independently mediated by a real runtime in this prototype.

The monitor's C14 check verifies that required arguments are present and that the target is a non-empty string. It does not validate every action-specific payload type or semantic constraint; a real executor must enforce those schemas before acting. Filesystem grant matching performs lexical path validation only; a real executor must also prevent
symlink escapes and TOCTOU races. Network integrations must resolve and re-check destinations and
redirects at connection time to reduce DNS-rebinding and redirect-based SSRF. A deployment must route
every consequential effect through an executor that verifies and consumes the monitor's single-use
token. The default monitor does not accept approvals unless the integrator supplies an
`approval_verifier` that validates a signed approval from a separately authenticated approval
service. The benchmark injects a test-only verifier and simulates the human decision; its digest
check is not an authentication mechanism and must not be reused in production.

**Provenance scope:** joined labels preserve all contributing tenant identifiers. The label
mechanism still depends on trusted adapters assigning correct labels and on integrations preserving
them across every transformation; it does not establish the truth of a source or protect against
a compromised adapter. The audit chain detects record alteration within the retained chain, but
is not an external, append-only log service.

## External framework integration

An optional adapter, a task-scoped workspace read/search mapper, and a paired
benchmark runner are available for the independently maintained AgentDojo benchmark.
Install the optional dependency with `pip install -e ".[dev,agentdojo]"`, then use
`paca-agentdojo --list-supported-tasks` and `paca-agentdojo --list-injection-tasks`
to inspect the installed suite. The runner requires explicit user-task and injection-task
IDs and can preflight applicable attack/task pairs and task policies without model calls. It compares
AgentDojo with no defence, AgentDojo's official `tool_filter`, and PACA++. Its supported
scope, configuration, metrics, limitations, and evaluation protocol are documented in
[docs/agentdojo-integration.md](docs/agentdojo-integration.md).

CI validates the runner and integrations without an LLM provider. A separate bounded real-model
benchmark job runs only when the repository's `OPENAI_API_KEY` secret is configured; it retains
raw task-level results as a CI artifact. No independent AgentDojo effectiveness scores are claimed
until that actual run completes successfully and its failed/skipped samples are inspected.

## DSL
```
C5: deny any when flow.excess > 0 with obligation audit_log   # data more sensitive than destination clearance
C15: permit merge_pr with obligation require_approval
```
`ID: permit|deny ACTION [when a.b OP v [and|or ...]] [with obligation x(y)]  # note`. `and` binds tighter than
`or`. Decisions are three-valued (`permit`/`deny`/`not_applicable`); the engine combines with `deny_overrides`
by default.

## Scenario source mapping
Reference strings such as `[1][14]` in scenario metadata are provisional source keys carried over
from working notes. This repository does not include a complete bibliography or a verified
key-to-source mapping. They are not publication-ready citations until that mapping is supplied
and checked. The scenarios are author-defined simulations, not an independently published attack catalog.

## What changed vs the previous repo state
The committed files had **contents shifted against their names** (e.g. the compiler in `compiler_asp.py`, the
provenance code in `obligations.py`, a README as `tests/test_parser.py`), two paths named with whole file bodies,
`import paca` failed, and the parser regex was compiled without the verbose flag so even the README example did
not parse. v0.3 rebuilds the package cleanly, fixes `deny` semantics (an unmatched deny used to return `permit`)
and operator precedence, and adds the monitor, labels, scenarios and benchmark.

Maturity: research prototype (Python, in-process monitor, self-authored deterministic benchmark,
optional AgentDojo tool-executor adapter, limited task-scoped workspace read/search mapper,
paired AgentDojo benchmark runner (real-model evidence is reported separately and is not inferred from CI adapter tests),
no full workspace write/effect mapping, no production executor, and no solver-backed verification).

## Quick‑Start

### Install the package and local reference API
```bash
pip install -e ".[dev,api]"
```

### Run the reference decision API locally
```bash
uvicorn paca_executor:app --host 127.0.0.1 --port 8000
```
The API exposes `GET /health` and `POST /decide` at **http://127.0.0.1:8000**.

### Run the container image
The workflow builds the Docker image on pull requests and pushes it to GitHub Container Registry only after a push to `main`.
```bash
docker pull ghcr.io/sanafirdouse2323-glitch/paca-plus-plus-new:latest
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/sanafirdouse2323-glitch/paca-plus-plus-new:latest
```
Binding the published host port to `127.0.0.1` keeps this local demonstration endpoint off public host interfaces.

### Example decision request
```bash
curl -X POST http://127.0.0.1:8000/decide \
  -H "Content-Type: application/json" \
  -d '{
        "action": "read_file",
        "args": {"path": "/acme/reports/summary.txt"},
        "capability": {
          "id": "c1",
          "principal": "local-demo-user",
          "tenant": "acme",
          "task": "task1",
          "role": "assistant",
          "grants": {"read_file": ["/acme/reports/summary.txt"]},
          "expires": 30
        }
      }'
```
The response reports the decision, fired checks, violations, digest, obligations, and whether the in-process reference token matched the same request. `effect_executed` is always `false`: the API does not read or write files, send mail, call tools, or perform any other external effect.

**Security boundary warning:** this is a local reference/demo API, not a production executor. It accepts capability data from the caller, does not authenticate a capability issuer, and cannot assign trusted resource labels on behalf of real connectors. The `expires` field is a monitor step limit, not a wall-clock expiry; a real integration must supply a trusted, monotonic step counter. Capability-use state and the audit state are process-local and are lost on restart. Do not expose it to untrusted networks or use its response as the sole authorization gate for real effects. A production integration must authenticate callers, obtain signed/task-scoped capabilities from a trusted issuer, assign provenance in trusted connectors, validate action-specific schemas, persist required state, and have the actual effect executor verify and consume a single-use token immediately before every side effect.

### Lint & type‑check
```bash
ruff check .
mypy paca paca_executor.py
```

These checks are also executed automatically in the GitHub Actions workflow.

## Licensing

**Current code and PACA++ v0.3.1:** The root [MIT License](LICENSE) applies to the code already distributed under MIT, including the v0.3.1 repository and image. MIT permits commercial use subject to its notice conditions; this project cannot retrospectively require royalties from recipients of those MIT copies.

**Future components:** The project is considering free academic/non-commercial access for separately identified new components, with commercial use available only under a separate written agreement that may include negotiated fees or revenue sharing. The proposed terms are a draft only and are not yet applied to any source file or release. See [LICENSING.md](LICENSING.md) and [LICENSE-ACADEMIC-DRAFT.md](LICENSE-ACADEMIC-DRAFT.md).

The proposed non-commercial terms are source-available, not OSI-defined open source. Do not assume they replace the MIT terms for existing files.
