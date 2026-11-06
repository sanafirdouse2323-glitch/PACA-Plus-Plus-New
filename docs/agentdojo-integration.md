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
   call made with the same capability within this executor instance; capability expiry
   values must use the same step scale. Use a distinct capability ID for each task.

The counter is in memory and is reset when the executor is recreated or the process
restarts. The adapter and reference monitor are not a concurrent, multi-worker
coordination service. Serialize calls through one executor instance per task. A
deployment that needs concurrent or restart-safe execution must provide an atomic,
durable step allocator and coordinate capability call budgets and token state outside
this adapter.

The adapter binds the full normalized AgentDojo tool argument object into the request
digest under a reserved field. It rejects a request builder that mutates the normalized
argument copy, then verifies and consumes the PACA++ token before calling
runtime.run_function with the original normalized argument snapshot. The reserved
field is included in the monitor's digest but is not interpreted as a policy attribute;
the request builder must still map each security-relevant value to the correct action
and provenance fields.

C13 effect-token verification is a structural requirement for this external executor
and cannot be disabled through Monitor's policy-check ablation setting. The adapter
rejects such a Monitor configuration at construction time.

## Task-scoped workspace read mapper

The repository includes `paca.integrations.agentdojo_workspace`, a concrete mapper
for a deliberately limited subset of AgentDojo's `v1.2.2` workspace suite. It maps
read/search calls into PACA++ read actions and fails closed for every unlisted tool.
It does not yet authorise writes, deletes, email sends, file sharing, or calendar
mutations.

Supported workspace tools:

- Email: `get_unread_emails`, `get_sent_emails`, `get_received_emails`,
  `get_draft_emails`, `search_emails`, `search_contacts_by_name`,
  `search_contacts_by_email`.
- Calendar: `get_current_day`, `get_day_calendar_events`,
  `search_calendar_events`.
- Cloud drive: `get_file_by_id`, `list_files`, `search_files`,
  `search_files_by_filename`.

The workspace suite also contains mutating tools. They are intentionally not in
`SUPPORTED_WORKSPACE_READ_TOOLS`; calls such as `send_email`, `delete_email`,
`create_calendar_event`, `cancel_calendar_event`, `reschedule_calendar_event`,
`add_calendar_event_participants`, `create_file`, `append_to_file`,
`delete_file`, and `share_file` are denied by this read-scoped mapper. This makes
the mapper suitable only for user-task slices whose legitimate tool calls are within
the supported read set. It is not a full workspace-suite policy.

### Configure a task-scoped mapper

The task capability and source labels are mandatory trusted inputs. The mapper does
not infer access rights from task text, tool names, file names, email contents,
calendar descriptions, or model output.

```python
from agentdojo.task_suite.load_suites import get_suite

from paca.integrations.agentdojo import PacaToolsExecutor
from paca.integrations.agentdojo_workspace import (
    WorkspaceTaskContext,
    make_workspace_request_builder,
)
from paca.monitor import Monitor
from paca.provenance import Label
from paca.runtime import Capability

suite = get_suite("v1.2.2", "workspace")

# Example authority for one read-only calendar task. This capability must be
# constructed from trusted benchmark/user-task setup, not from injected content.
capability = Capability(
    cap_id="workspace-user-task-1",
    principal="benchmark-user",
    tenant="workspace-v1.2.2",
    task_id="workspace:user_task_1",
    role="assistant",
    grants={
        "read_calendar": ("calendar:day:2024-05-15",),
    },
    expires=20,
    max_calls=10,
)

# Illustrative fixture-side labels only. Replace these with labels supplied by
# the evaluation's trusted fixture/connector metadata.
source_labels = {
    "mail": Label(
        integrity="untrusted", sensitivity=2, tenant="workspace-v1.2.2",
        origins=frozenset({"agentdojo_fixture:mail"}),
    ),
    "calendar": Label(
        integrity="untrusted", sensitivity=1, tenant="workspace-v1.2.2",
        origins=frozenset({"agentdojo_fixture:calendar"}),
    ),
    "drive": Label(
        integrity="untrusted", sensitivity=2, tenant="workspace-v1.2.2",
        origins=frozenset({"agentdojo_fixture:drive"}),
    ),
}

def label_workspace_resource(source, arguments, env):
    # A real experiment may inspect a trusted sidecar keyed by file ID, date,
    # or fixture record. Never classify from text written by the model.
    return source_labels[source]

context = WorkspaceTaskContext(
    capability=capability,
    resource_labeler=label_workspace_resource,
)
request_builder = make_workspace_request_builder(context)
monitor = Monitor()

# Insert PacaToolsExecutor before AgentDojo's runtime dispatcher in the
# ToolsExecutionLoop, as shown in the next section.
executor = PacaToolsExecutor(monitor, request_builder)
```

The mapper creates these capability targets:

| Source | Tool operation | Target scope |
|---|---|---|
| Mail | Unread, sent, received, drafts | `mail:inbox:unread`, `mail:sent`, `mail:received`, `mail:drafts` |
| Mail | Search messages or contacts | `mail:search`, `mail:contacts:name`, `mail:contacts:email` |
| Calendar | Current day | `calendar:current_day` |
| Calendar | Events for one day | `calendar:day:<YYYY-MM-DD>` |
| Calendar | Search events | `calendar:search:<YYYY-MM-DD>` or `calendar:search:all` |
| Drive | Retrieve one file | `drive:file:<file_id>` |
| Drive | List or search files | `drive:list:all`, `drive:search:content`, `drive:search:filename` |

Grant patterns should be as narrow as the task allows. For example, the exact grant
`read_calendar: ("calendar:day:2024-05-15",)` permits that date target, not other
calendar days. A search target covers the relevant mailbox/calendar/drive search
operation; search terms are separately included as untrusted, digest-bound request
arguments. Broad search grants therefore authorise broader reads and must be reported
as such.

The resource-label callback receives one of `mail`, `calendar`, or `drive`, a copy
of the normalised tool arguments, and the AgentDojo environment. It must return a
PACA++ `Label` from trusted evaluation metadata. If it raises or returns a non-Label,
the executor denies the call. The mapper conservatively marks model-provided query,
date, and file-ID arguments as untrusted and joins them with labels from prior tool
outputs when available.

The mapper is strict about argument keys and required values. Search queries must be
non-empty; calendar dates must be valid `YYYY-MM-DD` strings. Unexpected arguments,
unknown tool names, and unsupported mutating tools fail closed.

### Insert the adapter into an AgentDojo pipeline

The following shows the insertion point against AgentDojo's AgentPipeline factory.
Use the actual task-scoped `monitor` and `request_builder` configured above.

~~~python
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop

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
~~~

The model provider must be configured using AgentDojo's supported environment
variables/API credentials. The sample model name is illustrative; use an identical
model and configuration for each matched experimental condition.

**Evaluation boundary:** the initial PACA++ workspace experiment must select benign
user tasks whose legitimate ground-truth tool calls are all in
`SUPPORTED_WORKSPACE_READ_TOOLS`. Attacked runs may then test whether malicious
instructions attempt unsupported mutating calls. Report this as a read-scoped,
task-authorised experiment, not as coverage of all AgentDojo workspace tasks. Do not
compare its utility denominator with a full-suite baseline unless the task selection
is identical.

This mapper and its tests do not execute an LLM benchmark and do not establish
independent attack-success or utility measurements.

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
- A single-use PACA++ effect token prevents reuse of that token; it does not deduplicate
  separately authorised requests. Connectors for non-idempotent effects (for example,
  sending messages or making payments) must implement their own idempotency keys or
  equivalent duplicate-effect protection.
- The adapter does not provide transactional rollback when a connector fails after
  dispatch. Such failures can have an uncertain or partial external outcome.
- This adapter and the in-memory Monitor state are intended for serialized, single-
  executor use. They are not safe to treat as a concurrent multi-worker coordinator.
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
