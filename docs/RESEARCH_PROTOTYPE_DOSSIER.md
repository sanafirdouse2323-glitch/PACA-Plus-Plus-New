# PACA++ New: PhD research prototype

**Assessment date:** 28 November 2026  
**Project:** `PACA-Plus-Plus-New`  
**Current status:** Research prototype. It is not production-ready.  
**Lifecycle behavior baseline (PR #59):** `c45732707cbfccf44bc4903300250f21184aa128`  
**Repository snapshot reviewed:** `5cd0936710809108a661e81a5b1798049a6a26a3`; a later commit extracted the message codec without an intended behavior change.  
**Merged change:** [PR #59 — Bind agent communication and delegation to lifecycle sessions](https://github.com/sanafirdouse2323-glitch/PACA-Plus-Plus-New/pull/59)

This document describes `PACA-Plus-Plus-New` only. The separate `PACA-Plus-Plus` enterprise gateway is a different project, with a different codebase and evidence. The two should not be confused.

## 1. The research problem

An AI agent does not make one decision and then stop. It takes in information, retrieves and stores data, forms a plan, calls tools and may pass work to another agent. Eventually, one of those steps can change something outside the agent, such as a file or a service record.

A security check at the tool-call stage may not be enough. Information retrieved earlier may have lost its source details. A memory entry may be reused in a later task. A delegated agent may receive more authority than it needs. A policy or capability may also change between the time an action is planned and the time it is carried out.

This project asks whether those parts can be checked together, rather than treating each tool call as a separate event.

**Research question**

> Can an authorisation and usage-control model preserve information provenance and authority restrictions as an AI agent moves through retrieval, memory, planning, tool use, communication and effect execution? Can it prevent violations that the strongest relevant stage-specific controls do not catch, while still allowing legitimate tasks to finish?

**Working hypothesis**

> When provenance, delegated authority, usage limits and the final resource commit are checked as part of the same workflow, fewer unauthorised effects will reach a protected resource than with the strongest applicable stage-specific controls, without an unacceptable reduction in legitimate task completion.

This is a hypothesis, not a result. The current repository does not establish that the approach is better than existing systems. A policy returning “deny”, a model refusing a request or a passing unit test is not enough to show that an unauthorised action was prevented. The main evidence must come from the protected resource itself and from a trusted record of what it accepted.

## 2. Existing work and the research gap

There is already substantial work on tool authorisation, information-flow control, agent identity, delegation, multi-agent communication and effect commitment. The project must build on that work and compare against it fairly. It should not claim that capabilities, provenance tracking or reference monitors are new ideas.

The following papers and systems are relevant to the proposed study:

| Area | Existing work | Why it matters |
|---|---|---|
| Tool use and information flow | [CaMeL](https://arxiv.org/abs/2503.18813) and [Progent](https://arxiv.org/abs/2504.11703) | Relevant to keeping trusted instructions separate from untrusted data and restricting tool calls and arguments. |
| Communication between agents | [Multi-CaMeL](https://arxiv.org/abs/2610.05640), submitted 5 October 2026 | Shows why protections applied to individual agents may not be enough when agents pass information to one another. |
| Delegation and reference monitoring | [DelegateGuard](https://arxiv.org/abs/2610.16005), submitted 12 October 2026, and [Delegation Without Trust](https://arxiv.org/abs/2609.00267), submitted 31 August 2026 | Close comparisons for delegated permissions, capability restrictions, broker enforcement and compromised sub-agents. |
| Authorisation at the point of effect | [AID-Guard](https://arxiv.org/abs/2608.21159), submitted 21 August 2026 | Relevant to checking that an action is still authorised when a provider commits it, including retries and uncertain delivery. |
| Tool filtering in a benchmark | AgentDojo's native `tool_filter` | A baseline for the AgentDojo tasks that the current adapter supports. |

The papers listed above are recent preprints. Their reported results belong to the authors; they are not results obtained by PACA++ New. Any comparison must use the original implementation, a pinned version and the paper's stated threat model. A simplified implementation written for this project must not be presented as a reproduction of the original system.

The possible contribution is therefore not any single mechanism in this list. The question is whether a clearly specified combination of information provenance, authority, usage limits and resource-side checks can preserve the necessary restrictions across a connected workflow. The study must show where this combination adds protection over the strongest suitable existing controls. That has not yet been demonstrated.

## 3. What the model is intended to cover

The proposed study follows an agent through six stages:

1. **Input and retrieval.** Identify where information came from, which tenant and version it belongs to, and whether it can be trusted.
2. **Memory and context.** Keep that source information and its restrictions when data is stored, retrieved, summarised or reused in another session.
3. **Planning.** Treat a model's plan as a proposal. The plan itself must not grant permission to act.
4. **Tool execution.** Check the exact tool, implementation, arguments and authority before a configured runtime executes it.
5. **Communication and delegation.** Check who sent a message, who receives it, what information it carries and what authority is passed to the next agent.
6. **Effect authorisation and commitment.** Check the action again at the resource boundary and keep evidence of what was actually committed.

Four related questions run through these stages. Does the agent still have the right authority? Is the information's source and history still known? Have usage limits and replay protections been preserved? Did the action that reached the resource match the action that was authorised?

These questions are related, but they are not interchangeable. Trusted information does not automatically give an agent permission to use it. A valid capability does not make the data trustworthy. Consuming an authorisation does not prove that a resource accepted the action.

## 4. What is implemented

The README contains the current six-group map of the codebase. In broad terms, the repository contains:

- policy parsing and evaluation, a `Monitor`, a lifecycle controller and a runtime for selected PACA-managed calls;
- HMAC and Ed25519 capability paths, authority lineage, delegation and revocation, with SQLite and an optional PostgreSQL authority registry;
- provenance labels, lineage records, separate memory-value storage and selected connector, memory and framework adapters;
- local resource-commit controls, including a logical-resource fence, an optional Linux filesystem writer and selected broker paths;
- optional Docker and Linux helpers for selected execution and I/O paths; and
- adapters for AgentDojo, LangChain, LangGraph/checkpoints and selected read-only provider ingress.

These are separate pieces with different boundaries. They are not six complete layers that are always active together. For example, the PostgreSQL registry is not a complete distributed lifecycle store, the Docker worker is not a mandatory operating-system sandbox, and the provider adapters do not protect arbitrary calls made directly to a provider.

Formal models, tests and benchmark tools help examine the implementation. They are not additional runtime enforcement layers.

### Lifecycle-session checks for communication and delegation

The Phase A audit identified one specific gap. When `lifecycle_security` was configured, `PACAAgentRuntime.execute_effect()` checked selected effect requests against the active session. However, `delegate()`, `send_message()` and `receive_message()` did not apply the same session check.

The change merged in PR #59 adds that check to those three runtime methods. Before delegation, the runtime verifies the parent capability and its authority lineage. Before sending or receiving a message, it verifies the relevant sender or recipient capability. The principal, tenant, task, purpose and policy epoch must match the active lifecycle session.

The actual delegation and message work still goes through the existing authority issuer and message codec. The issuer remains responsible for restricting a child's permissions and tool pins. The message codec continues to check message authentication, recipient permissions, provenance, revocation and replay. The new session check does not replace those controls.

The runtime performs the local adapter operation while holding the lifecycle controller's lock. It also checks the session again after the audit callback, because trusted host audit code can call back into the controller. This prevents an audit callback from stopping or replacing the session and then allowing the operation to continue.

This change only covers calls made through the configured `PACAAgentRuntime`. It does not intercept direct calls to the issuer or message codec, or calls made through other frameworks, transports or host APIs.

## 5. Demonstration and tests

The merged `main` branch includes a small offline example at `examples/lifecycle_security_demo.py`. It uses local SQLite stores and two agents. It does not call an LLM or a live provider.

The example runs two cases. In the first, a source is marked trusted by the host-configured test connector. One agent retrieves it, delegates limited authority to a second agent and sends the data in a signed message. The receiving agent checks its session and attempts a write through the local SQLite resource fence. The example checks the resulting resource record, including its version, authority identifier, request digest and commit nonce.

The second case follows the same route, but the source is labelled untrusted. The receiving agent may receive the data, but the consequential write must be denied. The test checks that no resource record was created.

The plan in these tests is fixed test data. It is not produced by an LLM, and the example does not inspect a model's hidden reasoning. The source labels also come from trusted test configuration. This is a demonstration of the declared local path, not a live-agent experiment.

Additional tests in `tests/test_lifecycle_communication.py` cover session mismatches, successful delegation, message sending and receiving, rejection before message receipt consumption, the kill switch and a re-entrant audit callback. `tests/test_lifecycle_demo_cli.py` runs the example itself and checks both outcomes.

To run the example and the focused tests from the repository root:

```bash
python -m pip install -e ".[dev]"
python examples/lifecycle_security_demo.py --output /tmp/paca-lifecycle-demo.json
python -m pytest tests/test_lifecycle_communication.py tests/test_lifecycle_demo_cli.py -q
```

## 6. Threat model and limitations

The tests consider untrusted retrieved content, indirect prompt injection, memory poisoning, loss of provenance, over-broad delegation, stale or replayed authority, policy changes, revocation races, duplicate requests and attempts to bypass the configured runtime.

The local prototype trusts the host application to establish the session, the connector to identify and label its source, the configured issuer and its keys, the policy engine, the executor mapping, the local registry and the resource used to check the result. These components are part of the trusted computing base for the tests.

The current work does not solve a compromised host or issuer, arbitrary discovery of hidden model-context dependencies, semantic truth verification, or complete mediation of raw stores, direct framework calls, subprocesses and network paths. It also does not provide production OIDC or workload identity, KMS/HSM key custody, a single atomic transaction across every store, or general commit and recovery guarantees for SaaS providers. Availability, side-channel resistance and broad denial-of-service protection have not been established either.

The demonstration uses a permissive memory metadata callback so that it can focus on the lifecycle and provenance path. It does not replace the separate memory-policy tests. The HMAC keys in the example are for demonstration only and must not be used in a deployment. A SHA-256 digest helps identify the data recorded in an event; it does not encrypt that data or prove that the source is truthful. Audit records still need access controls and appropriate retention.

## 7. What the validation shows

The results below apply to the merged implementation commit `c45732707cbfccf44bc4903300250f21184aa128` on `main`.

Main-branch CI run #1062 (`46165972063`) passed the Python 3.10–3.13 test matrix, Ruff checks, all three installation-profile security contracts, broker UID isolation, AgentDojo adapter tests, LangGraph integration, PostgreSQL checkpoint integration, wheel smoke tests and the Docker build. The credential-dependent `agentdojo-real-benchmark` job was skipped. No live-model experiment or result is claimed.

Main-branch release-validation run #841 (`46165972095`) passed the complete test suite, configured security-critical type checks, lint and formatting, installation-profile contracts, broker isolation, and wheel and source-distribution build and smoke tests. The tag-specific GitHub Release and container publication steps were skipped because this was a normal `main` push.

PR #59 is merged. No independent security review is recorded. The repository's `main` branch is still unprotected (`protected: false`) and the rulesets endpoint was empty when checked on 28 November 2026. An administrator still needs to apply and verify the ruleset described in the security-configuration guide.

These checks show that the tested code paths and package checks passed. They do not show complete lifecycle mediation, production readiness or independent security assurance.

## 8. Work still needed for the research study

The next step is not to add more components simply to make the architecture larger. The study first needs to establish where existing controls succeed and where they leave a real gap.

The evaluation should begin by fixing the threat model, policy and test scenarios. It should then run the strongest suitable existing baseline in its original, pinned configuration. Only after reproducing a remaining failure should a new PACA mechanism be added or claimed as necessary.

The experiments should cover changes to information as it is rewritten, summarised, compacted, retrieved and passed between agents. They should also test revocation, repeated requests, concurrent actions, timeouts, process restarts and recovery after an uncertain commit. A live model should be added only with a pinned configuration and retained traces, so model behaviour can be separated from enforcement behaviour.

The main measures should include unauthorised effects at the resource, legitimate task completion, false denials, indeterminate outcomes, latency, token use and cost. The confirmatory study should use separate workflow templates, predeclared outcomes and an appropriate sample size. Rephrasing the same scenario several ways does not create several independent workflows.

The current AgentDojo work is an adapter and harness pilot. It is not a completed comparative study. CaMeL, Progent, Multi-CaMeL, DelegateGuard, Delegation Without Trust and AID-Guard must be tested using their own implementations and stated assumptions before any performance comparison is made.

## 9. What can be claimed now

The repository contains reference implementations for policy evaluation, capability authority, provenance-aware memory, selected local resource commits, optional execution containment and selected framework adapters.

The lifecycle controller checks selected effect requests against an active session. The change merged in PR #59 extends that check to delegation and inter-agent messages made through the configured runtime. The deterministic local example shows one benign delegated-message-to-resource-write path and one case where untrusted memory is denied before a resource record is created.

Those statements describe the current implementation and tests. The following stronger claims are not supported: complete lifecycle mediation, protection against prompt injection across arbitrary models and frameworks, production-grade identity or key management, general remote-provider commit safety, superiority over the related research systems, successful live-model evaluation or independent security certification.

PACA++ New is a research prototype with a working local example and clearly stated limitations. It gives the proposed PhD work a concrete system to investigate. Whether the combined controls provide additional protection over the strongest existing systems remains an open question, and the planned experiments must answer it.

## 10. Related project documentation

- [README and implementation map](../README.md#what-is-implemented)
- [Lifecycle enforcement and its boundaries](AGENT_LIFECYCLE_ENFORCEMENT.md)
- [Phase A audit and threat model](LIFECYCLE_PHASE_A_BASELINE_AUDIT.md)
- [AgentDojo pilot profile](PHASE_A_AGENTDOJO_PILOT_PROFILE.md)
- [Communication and delegation integration](LIFECYCLE_COMMUNICATION_INTEGRATION.md)
- [Six-point comparative evaluation protocol](SIX_POINT_INDUSTRY_EVALUATION_PROTOCOL.md)
- [Policy-continuity evaluation](POLICY_CONTINUITY_EVALUATION.md)
- [Direct-bypass evaluation](DIRECT_BYPASS_EVALUATION.md)
- [Seven security requirements](SEVEN_REQUIREMENTS_STATUS.md)
- [Repository security configuration](REPOSITORY_SECURITY_CONFIGURATION.md)

