# Policy-continuity evaluation

**Status:** an implementation and evaluation contract for the PACA-managed
runtime. It is not a claim that PACA++ provides complete mediation across an
enterprise deployment.

## Security objective

PACA++ evaluates whether a security-relevant fact remains bound from its source
through delegation and transformation to the externally committed effect. The
reference runtime makes four dimensions explicit:

| Dimension | Required invariant | Current PACA hook |
|---|---|---|
| Authority continuity | The active principal, tenant, task, purpose and policy epoch remain bound to the request, delegation and message operations; delegation cannot broaden the immutable grant chain. | `LifecycleSecurityController`, `AuthorityLineageGraph`, capability verification and registry revocation; configured `PACAAgentRuntime` session checks for delegation and message send/receive |
| Information continuity | Sensitive or untrusted information cannot become an effect argument without complete lineage, tenant compatibility and a trusted adapter boundary. | `Arg.lineage_refs`, `lineage_incomplete`, `Label`, `TrustedMemoryAdapter` and lifecycle checks |
| Usage continuity | A retry or duplicate call cannot silently reuse the same effect authorization; quotas and monitor decisions remain part of the final path. | monitor effect token, authority usage registry and one-use lifecycle request digest |
| Effect continuity | The final action, arguments, tool identity and policy-relevant metadata are the same frozen values that were authorized. | request digest, snapshot checks, typed digest-pinned tool and `commit_authorization()` |

These invariants are conditional on the relevant operation being routed through
`PACAAgentRuntime` and its configured adapters with `lifecycle_security` enabled
for the lifecycle-session checks. Direct provider clients, raw database handles,
host subprocesses, unrestricted network paths, direct issuer/codec calls and
unmediated framework callbacks remain deployment bypasses until the surrounding
system removes or separately enforces them.

## What this implementation rejects

For operations routed through the configured runtime and lifecycle controller,
the applicable checks fail closed when:

- no active session binds an effect, delegation or message operation to the intended principal, tenant, task, purpose and policy epoch;
- the capability has no immutable authority lineage, or its purpose/policy epoch
  does not match the active session binding;
- a consequential action has no typed tool manifest or its implementation is
  not digest-pinned;
- an effect argument is untrusted, tenant-unknown, tenant-mismatched or marked
  as having incomplete lineage;
- the request digest changes between snapshot, policy decision and commit; or
- the same frozen effect digest is committed more than once.

The controller stores audit metadata only: phase, operation, identities,
decision, reason and digests. It does not store model prompts, retrieved text,
credentials or effect payloads.

The lifecycle controller's one-use request-digest cache is bounded and process-local. It fails closed at its configured capacity but is not persisted or shared across replicas. The tool manifest digest is capability-pinned; the generic Python executor callable remains trusted host configuration and is not independently hashed by the controller. Evaluation must test executor substitution and must not treat these mechanisms as durable distributed replay protection or host isolation. The controller's `session_id` is local audit context and is not carried in the authenticated request/transport; test the host-side mapping from authenticated workload identity to session context.

## Transformation and stateful test protocol

The deterministic test suite should keep the following attack families as
separate rows, with the same task identity and sink observed for every row:

1. direct and indirect prompt injection, including tool-returned instructions;
2. paraphrase, summarisation, extraction and reconstruction of a labelled value;
3. retrieval and memory poisoning, memory extraction and cross-session reuse;
4. delegation, policy-epoch change, revocation and purpose/tenant mismatch;
5. concurrent requests, retries, timeouts, duplicate delivery and uncertain
   external outcomes;
6. malicious or substituted tools, inter-agent transfer and destination drift; and
7. executor substitution, stale tool manifests, controller restart, receipt-capacity exhaustion and duplicate requests routed through separate controller instances.

For each row, record at least:

- unsafe-action rate and privilege-escalation distance;
- legitimate completion rate and false-denial rate;
- indeterminate/uncertain outcome rate;
- time, throughput, latency and resource cost; and
- the complete decision/commit trace plus the observed sink state.

The repository's `tests/test_lifecycle_communication.py` also checks selected
session-bound delegation and message routes, including sender/recipient mismatch,
message-receipt ordering, the kill switch and audit-callback re-entry. These are
focused regression tests, not evidence of full multi-hop or transport-wide
mediation. See [the communication integration notes](LIFECYCLE_COMMUNICATION_INTEGRATION.md).

Prompt-level refusal is not a sufficient success criterion. A row passes only
when the intended security property holds and the executable sink shows no
unauthorized side effect. Model-generated adaptive attacks are a supplementary
stress test; scripted cases remain the reproducible regression baseline.

## Baseline and claims discipline

Freeze the comparison baseline without the proposed combined continuity
controls before measuring their contribution. Compare the same agent, model,
tools, task set, timeouts and sink protocol with and without the configured
lifecycle controls. Report the residual bypasses instead of converting benchmark
results into a universal security claim.

Research findings motivate this design: tool-using agents remain vulnerable to
indirect injection and memory/tool abuse; deterministic least-privilege and
context isolation are promising; and semantic compliance can diverge from
observed harm. Those findings do not establish that this implementation is
production-safe, that cryptographic provenance solves poisoning, or that local
authorization can make a remote provider commit atomic with revocation.

Production deployment still requires enforced process/OS isolation, workload
identity and key custody, short-lived secret brokering, network and destination
allowlists, provider-side conditional commits, independent stop/quarantine,
tamper-resistant audit, protected delivery configuration and external
adversarial review.

