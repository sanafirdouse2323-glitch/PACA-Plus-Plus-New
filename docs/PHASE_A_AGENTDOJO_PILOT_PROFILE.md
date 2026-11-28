# Phase A candidate profile — bounded AgentDojo workspace pilot

**Repository:** `PACA-Plus-Plus-New` only.  
**Profile version:** 0.1 (28 November 2026).  
**Implementation baseline:** PR #49 merge `c9d06c4796a9fb0a04cd5db1ca4c792d2396506a`.  
**Status:** proposed executable pilot profile; not preregistered, not independently approved, and not run live.  
**Purpose:** validate the existing AgentDojo comparison harness on a narrow supported task subset before attempting a broader lifecycle study.

## 1. Why this is the first runnable pilot

The repository already has a bounded AgentDojo workspace adapter and a runner that invokes three conditions on the same selected tasks and attack pairs:

1. AgentDojo with no defense;
2. AgentDojo's native `tool_filter` defense; and
3. PACA's current AgentDojo adapter/policy.

The dependency is pinned in `pyproject.toml` to `agentdojo==0.1.35`. The mapper is pinned to AgentDojo suite data version `v1.2.2`. The CI workflow and adapter tests exercise the CLI, dry-run preflight and official `tool_filter` configuration. The live model requests were skipped in the latest inspected CI run because `OPENAI_API_KEY` was unavailable.

This is the most defensible first *harness pilot* because it reuses the actual benchmark and its native defense. It does not substitute a hand-authored approximation for AgentDojo's defense.

## 2. Frozen candidate configuration

| Field | Candidate value | Qualification |
|---|---|---|
| Benchmark package | `agentdojo==0.1.35` | Exact dependency pin in `pyproject.toml`; re-check the installed package metadata in the resulting artifact. |
| Suite data version | `v1.2.2` | The PACA workspace mapper rejects other suite versions until separately reviewed. |
| Suite | `workspace` | Only the workspace suite is supported by this runner. |
| User tasks | `user_task_1,user_task_16` | The current CI dry-run explicitly checks these. They are the supported calendar-read and email-search examples, not a representative sample of the whole suite. |
| Attack | `tool_knowledge` | The current CI dry-run selects compatible injection pairs for this attack. |
| Injection task IDs | All IDs returned by the pinned suite's `--list-injection-tasks` command | The runner computes and records applicable and skipped task/attack pairs. Do not assume every injection task applies to both user tasks. |
| Model identifier | `gpt-4o-mini-2024-07-18` | Existing CI dry-run configuration; availability and provider access must be confirmed before a live run. |
| Iteration limit | `12` | Matches the current workflow's bounded live-run configuration. |
| Conditions | no defense; native `tool_filter`; PACA | The runner executes these three actual configurations, with separate task pipelines and fresh PACA task capabilities. |

This table describes a candidate pilot, not a frozen confirmatory protocol. Before any billable live execution, record the current code commit, Python version, operating system, package metadata, model/provider identifier, date, applicable attack-pair count, omitted pairs and policy manifest from the dry-run output.

## 3. Exact preflight procedure

Install the repository's AgentDojo extra in a clean environment:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev,agentdojo]"
```

Enumerate injection tasks and construct the explicit candidate input list:

```bash
paca-agentdojo --list-injection-tasks > /tmp/agentdojo-injection-tasks.json

python - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("/tmp/agentdojo-injection-tasks.json").read_text())
ids = data["injection_task_ids"]
if not ids:
    raise SystemExit("The pinned suite returned no injection task IDs")
Path("/tmp/agentdojo-injection-ids.txt").write_text(",".join(ids))
print(f"Enumerated {len(ids)} injection task IDs")
PY
```

Run the non-billable dry-run preflight:

```bash
paca-agentdojo \
  --model gpt-4o-mini-2024-07-18 \
  --user-tasks user_task_1,user_task_16 \
  --injection-tasks "$(cat /tmp/agentdojo-injection-ids.txt)" \
  --attack tool_knowledge \
  --max-iters 12 \
  --dry-run > /tmp/agentdojo-phase-a-preflight.json
```

Review the JSON before any live run. It must identify the suite and version, both requested user tasks, the task-derived capability manifests, at least one applicable attack pair, and every skipped pair with a reason. Stop if the mapper rejects a task, if no attack pair is eligible, if the ground-truth manifest differs from the intended policy, or if the model identifier is not supported by the installed AgentDojo version.

The dry-run does not instantiate the model pipeline or make model/API requests. Passing it is configuration validation only.

## 4. Live pilot command and cost gate

A live run requires an authorised OpenAI API credential supplied through a protected local environment or a GitHub Actions secret named `OPENAI_API_KEY`. Never put a key in a commit, issue, log, command history, or chat.

Before starting, set an explicit provider-spend cap outside the repository and obtain approval for the expected pilot spend. This profile does not prescribe a dollar budget because no billing rate, account budget or spend authorisation has been supplied. If the credential or approved spend cap is unavailable, leave the live run blocked; do not replace it with a simulator and do not claim that the experiment ran.

Use a unique output directory for every attempt so that partial logs cannot be overwritten:

```bash
RUN_ID="phase-a-agentdojo-$(date -u +%Y%m%dT%H%M%SZ)"
paca-agentdojo \
  --model gpt-4o-mini-2024-07-18 \
  --user-tasks user_task_1,user_task_16 \
  --injection-tasks "$(cat /tmp/agentdojo-injection-ids.txt)" \
  --attack tool_knowledge \
  --max-iters 12 \
  --log-dir "runs/$RUN_ID/logs" \
  --output "runs/$RUN_ID/results.json"
```

The runner is sequential. It does not currently expose randomised condition order or a run-level seed in its CLI. Preserve this as an exploratory harness pilot; do not use one execution of this profile as a confirmatory treatment estimate or a basis for a superiority claim. Preserve the complete JSON output, per-condition AgentDojo logs, preflight file, environment/package metadata and hashes. A failed or interrupted run remains failed/partial; do not silently discard it and rerun under the same run ID.

## 5. Outcomes to inspect

Report by user task, injection task and condition:

- native AgentDojo attack-success outcome, with the runner's explicit indeterminate/operational-error classification;
- benign task utility and attacked-task utility;
- explicit PACA policy denials, approval-required decisions and unobserved required calls, using the runner's manifest-matched denominator;
- attempted, scored and indeterminate attack-pair counts;
- model request counts, errors, provider-reported input/output/total tokens and request latency where returned;
- episode latency and sequential episode rate, clearly labelled as sequential rather than concurrent throughput; and
- all eligible and skipped task/attack pairs.

Do not convert token totals to dollar cost. A dollar-cost result requires the actual provider/model billing schedule for the run date and suitable billing evidence, including any cached/reasoning-token treatment. The runner's target digest is an unkeyed SHA-256 matching value, not encryption or a confidentiality guarantee; protect result artifacts accordingly.

A run is eligible to be called a *completed pilot execution* only when the three conditions have completed for all predeclared eligible pairs, raw logs/results are retained, and infrastructure errors and indeterminate outcomes are separately disclosed. Completion is not evidence that PACA is better. No numeric pass threshold is specified here because the purpose is instrumentation and protocol validation, not hypothesis confirmation.

## 6. Exact scope boundary — what this pilot cannot establish

This pilot covers a selected AgentDojo workspace read-tool mapping and a limited `tool_knowledge` attack subset. It can provide a bounded comparison of the native tool-filter defense and PACA's adapter on those tasks. It does **not** test or establish:

- complete input/retrieval capture or source truth;
- persistent memory poisoning, compaction or cross-session memory enforcement;
- internal model planning or hidden reasoning;
- multi-agent message transfer, delegation or Multi-CaMeL's native protocol;
- host-level, subprocess, database or framework complete mediation;
- local filesystem or remote-provider mutation;
- destination-side commit authorization, reservation, idempotent delivery or crash recovery;
- a unified `LifecycleSecurityController` session spanning all six lifecycle stages; or
- protection across all AgentDojo tasks, frameworks, models, vendors or real deployments.

The selected workspace tasks are read-oriented. AgentDojo's native security/utility outcome is the oracle for this benchmark slice; it is not a destination-side commit receipt for a consequential write. The pilot therefore covers a limited part of tool execution and benchmark-visible information disclosure, not all six stages.

The runner executes conditions in a fixed order and does not expose a seed or randomisation control. Model responses may be stochastic. Any results are exploratory, and task/attack pairs derived from one underlying task must not be counted as independent workflow templates for the six-point statistical analysis.

## 7. Comparator separation and next study

- **AgentDojo `tool_filter`:** the actual native defense in this pilot; not a PACA-authored imitation.
- **No defense:** a negative control within the same benchmark runner.
- **PACA:** the current adapter/policy treatment, not a complete lifecycle treatment.
- **Multi-CaMeL / individual CaMeL:** separate native multi-agent study. The public `james-pete/multiagentdojo` artifact is a candidate source; its README identifies the MultiAgentDojo and multi-CaMeL implementation and its own Sequrity/API dependencies. It has not been installed, pinned into this repository, mapped to a common task subset, or executed here. Do not substitute PACA's signed message codec for its native protocol.
- **AID-Guard:** separate commit/reservation/recovery study. Its published provider-contract assumptions and sink-side evidence must be reproduced; PACA's local broker write mediator is not AID-Guard and is not an equivalent remote-provider comparator.
- **CaMeL and Progent:** separate native single-agent information-flow and typed-tool-policy studies. Documentary source records are not live execution.

The local resource paths must also remain separate in the analysis. `PACAAgentRuntime` with `FencedResourceExecutor` is the runtime's selected local logical-resource commit path. `InProcessBrokerWriteMediator` is a separate signed local logical-file protocol path with durable operation/idempotency receipts. The latter is not wired into the former's lifecycle-controller session; combining their test results would falsely imply a single integrated lifecycle-and-commit guarantee.

## 8. Pilot decision record

After the dry-run and, if authorised, the live pilot, append a dated result record containing:

- exact PACA repository commit and AgentDojo artifact/package version;
- model/provider identifier and date, with credential presence recorded only as a boolean;
- exact task IDs, applicable attack pairs and skipped-pair reasons;
- preflight and execution status for each of the three conditions;
- raw artifact paths and SHA-256 hashes;
- model request/token/latency summaries, errors and indeterminate outcomes;
- benign utility and attack outcomes by task/pair; and
- explicit statement that the pilot does not evaluate the full six-stage hypothesis.

Do not edit the comparator matrix from `D / not_run` to a reproduced result until an actual native run has completed and its raw evidence has been reviewed. Do not use this pilot to claim lifecycle-wide superiority or to mark Phase A complete.
