# PACA++ integration with AgentDojo

## Purpose and scope

This adapter places the PACA++ reference monitor immediately before the AgentDojo
FunctionsRuntime dispatch performed by ToolsExecutor. It is an integration point
for an independent evaluation harness, not a claim that PACA++ is production-ready.

AgentDojo is an external, independently maintained benchmark for prompt-injection
attacks against tool-using agents. The adapter is intended to let the same AgentDojo
suite, task, attack, and model configuration run with PACA++ inserted at the tool
execution boundary.

AgentDojo's API is marked as under development by its maintainers. This adapter
therefore targets the documented ToolsExecutor / BasePipelineElement interface
and pins the optional dependency version used in CI. Revalidate it when upgrading
AgentDojo.

## Installation

From the repository root:

~~~bash
python -m pip install -e ".[dev,agentdojo]"
~~~

The adapter is optional; the base PACA++ package remains dependency-free.

## Required application policy mapping

PACA++ cannot safely infer authorisation from a tool name or from an LLM-generated
argument. The application must supply a request_builder(function_name, arguments,
env, extra_args) callback. It is responsible for:

1. Selecting a PACA++ action for each registered AgentDojo function. Unknown functions
   must raise rather than receive a permissive default.
2. Creating a task-specific Capability from trusted task/application context, not
   from instructions found in retrieved content.
3. Assigning Arg labels from trusted connectors or the benchmark environment.
   Model-generated arguments are untrusted unless independently established otherwise.
4. Mapping every effect-relevant field (including recipients, attachments, query
   strings, amounts, and destinations) into the corresponding PACA++ request fields.
5. Setting Request.resource for reads when the connector can authoritatively determine
   the sensitivity and tenant of the resource before returning it.
6. Propagating provenance into later tool-call payloads. When fine-grained lineage is
   unavailable, use aggregate_prior_output_labels(extra_args) as a conservative
   fallback; this can cause false blocks but must not silently upgrade data to trusted.
7. Providing an integer Request.step. The adapter advances it monotonically for each
   call made with the same capability; capability expiry values must use the same
   step scale. Use a distinct capability ID for each task.

The adapter binds the full normalized AgentDojo tool argument object into the request
digest under a reserved field. It then verifies and consumes the PACA++ token before
calling runtime.run_function with that exact argument snapshot. The reserved field
is included in the monitor's digest but is not interpreted as a policy attribute;
the request builder must still map each security-relevant value to the correct action
and provenance fields.

## Insert the adapter into an AgentDojo pipeline

The following shows the insertion point against the AgentDojo AgentPipeline factory.
request_builder and monitor must be constructed for the selected benchmark task and
environment. This example deliberately does not invent a universal policy mapper.

~~~python
from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.task_suite.load_suites import get_suite

from paca.integrations.agentdojo import PacaToolsExecutor

# Application-specific components: these must be implemented for the selected
# benchmark task and environment using trusted task grants and connector labels.
# Do not derive either one from injected content or model-generated claims.
monitor = make_task_scoped_monitor()
request_builder = make_workspace_request_builder()

suite = get_suite("v1.2.2", "workspace")
pipeline = AgentPipeline.from_config(
    PipelineConfig(
        llm="gpt-4o-2024-05-13",
        model_id=None,
        defense=None,
        tool_delimiter="tool",
        system_message_name=None,
        system_message=None,
    )
)

tools_loop = next(
    element for element in pipeline.elements
    if isinstance(element, ToolsExecutionLoop)
)
tools_loop.elements = [
    PacaToolsExecutor(monitor=monitor, request_builder=request_builder),
    *tools_loop.elements[1:],
]

attack = load_attack("tool_knowledge", suite, pipeline)
results = benchmark_suite_with_injections(
    agent_pipeline=pipeline,
    suite=suite,
    attack=attack,
    logdir=Path("./runs/paca-agentdojo"),
    force_rerun=True,
    benchmark_version="v1.2.2",
)
print(results)
~~~


The names `make_task_scoped_monitor()` and `make_workspace_request_builder()`
in this example are placeholders for application-supplied implementations; they are
not functions exported by PACA++ or AgentDojo. The mapper must be written and reviewed
for the concrete suite/task before running the experiment.

The model provider must be configured using AgentDojo's supported environment
variables/API credentials. The sample model name is illustrative; keep the model,
suite version, tasks, attack, and model settings identical across baseline and PACA++
runs. This documentation does not claim that an AgentDojo benchmark run was executed
as part of this repository's CI.

## Approval behavior

The adapter fails closed on needs_approval unless an approval_provider is supplied.
If one is supplied, it must return an opaque token accepted by the Monitor's
approval_verifier, which must validate evidence from a separately authenticated
approval service. A callback that returns True, a user prompt string, or the
benchmark's ground-truth attack flag is not an authenticated approval mechanism.

## Current limitations

- The adapter intercepts AgentDojo function dispatch through ToolsExecutor; it does
  not independently mediate LLM planning, system/user messages, hidden state, tool
  descriptions, or all non-function-tool surfaces.
- The application policy mapper and task-specific capability issuance are not
  supplied automatically. A weak mapper can invalidate the security argument.
- Output labels are stored in extra_args under unique result-event keys; the mapper must
  explicitly use them when labelling downstream derived data. The adapter cannot infer
  exact LLM data lineage.
- The tool's underlying function remains responsible for validating action-specific
  semantics and ensuring the actual external effect matches the authorised request.
- This adapter does not wrap AgentDojo's hosted model provider, nor does it eliminate
  model/provider nondeterminism.
- A green adapter test is an integration/API smoke test, not an independent security
  result or a deployment certification.

## Reproducible comparison protocol

Use the same AgentDojo release (v1.2.2 suite data), model snapshot, suite, user-task
selection, injection-task selection, attack implementation, system prompt, tool-output
format, maximum iteration count, and retry policy for every condition.

At minimum, report these conditions separately:

1. AgentDojo stock pipeline with no defense.
2. AgentDojo stock pipeline with its tool_filter defense.
3. AgentDojo stock pipeline with spotlighting_with_delimiting.
4. PACA++-wrapped AgentDojo tool executor using an explicitly documented request mapper.

Do not call the stock defenses implementations of OPA, NeMo Guardrails, or the
OpenAI Agents SDK. They are AgentDojo's own named defense configurations. OPA,
NeMo Guardrails, and OpenAI Agents SDK require separate, correctly configured
integrations if they are to appear as experimental baselines.

Run benign tasks separately from attacked tasks. Report at least:

- benign utility (fraction of benign user tasks completed);
- utility under attack;
- targeted attack success rate using AgentDojo's environment state checks;
- number of tool calls denied, approved, and executed;
- false blocks on benign tasks;
- approval count and approval policy;
- wall-clock latency and policy-decision overhead;
- model, package, suite, attack, task IDs, configuration, and run artifacts.

Publish the raw task-level results and failed/skipped samples. Do not silently exclude
errors or blocked model outputs from denominators. Report denominators explicitly and
rerun stochastic conditions across multiple seeds where supported.

## Claims boundary

The existing PACA++ paca bench scores are from scenarios authored in this repository.
They must not be combined with AgentDojo scores or presented as AgentDojo results.
No comparative effectiveness claim should be made until actual AgentDojo runs have
completed under a documented, matched configuration.
