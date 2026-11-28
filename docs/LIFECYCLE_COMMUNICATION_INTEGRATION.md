# Lifecycle communication and delegation

**Repository:** `PACA-Plus-Plus-New`  
**Implementation:** `PACAAgentRuntime`  
**Branch:** `research/lifecycle-session-communication-2026-11-28`  
**Status:** Implemented on the PR branch. The code revision passed CI run #1050 and release-validation run #829. It has not been merged into `main` or independently security-reviewed.

## Why this change was needed

The lifecycle controller already checked selected effect requests against an active session. The same check was missing from three other runtime operations: `delegate()`, `send_message()` and `receive_message()`.

The authority issuer and message codec already performed their own checks. They verified permissions, message authentication, provenance, revocation and replay state. The gap was that they did not also establish that the operation belonged to the session currently represented by the runtime's lifecycle controller.

This meant that a valid capability for one principal or task could be presented to a runtime whose active session represented someone else. PR #59 adds a session check to those three runtime methods.

## What changed

The new check is used only when `lifecycle_security` is configured on `PACAAgentRuntime`.

For delegation, the runtime verifies the parent capability and its immutable authority lineage. It records a digest of the delegation request, including the requested child tool pins, and checks that the parent's principal, tenant, task, purpose and policy epoch match the active session. The existing authority issuer then creates the child capability and applies its normal restrictions. The issuer remains responsible for checking that the child receives no more authority, quota or tool access than the parent can delegate.

For message sending, the runtime verifies the sender capability and lineage before passing the message to the existing codec. It calculates a digest from the typed payload and its provenance information. The codec still checks the recipient grant, memory access, lineage, revocation and message authentication.

For message receiving, the runtime verifies the recipient capability and checks it against the recipient's active session before calling the codec. A session mismatch is therefore rejected before the codec consumes the message receipt or memory-read budget. The codec continues to perform its own signature, sender, recipient, provenance, replay and memory checks.

The local adapter operation runs while the lifecycle controller holds its lock. This prevents a concurrent `stop()` or `close_session()` from changing the session between the check and the adapter call. The controller also checks the session again after invoking the audit callback. That second check matters because trusted host audit code can call back into the controller and stop or replace the session.

The helper used for this work is an internal runtime method. It is not intended to be an authorisation API for applications, and its callback must remain a PACA-owned adapter operation. It accepts only the intended delegation and message transition types.

## Tests and runnable example

The change includes focused tests in `tests/test_lifecycle_communication.py`. They check that:

- delegation is rejected when the parent capability does not match the active session;
- valid delegation is recorded against the session;
- message sending is checked against the sender's session;
- message receiving is checked against the recipient's session before the message receipt is consumed;
- the kill switch blocks a message operation; and
- an audit callback cannot stop the session and still allow the operation to run.

The tests also cover a connected local workflow. A host-configured connector supplies a versioned source. The sender retrieves it, records the input and retrieval events, delegates limited authority, and sends the data to a second agent. The receiving agent checks its session and submits the received value to `PACAAgentRuntime.execute_effect()`, which uses the packaged `Monitor` and `SQLiteFencedResourceExecutor`.

There are two cases. The trusted-source case writes a row to the local resource registry. The test checks the version, child authority ID, request digest and commit nonce. The untrusted-source case is denied, and the test confirms that no resource row was created. The plan and source data are fixed test inputs; the example does not call an LLM or claim to test hidden model planning.

The branch also includes `examples/lifecycle_security_demo.py`, a standalone two-case example. `tests/test_lifecycle_demo_cli.py` runs that example as a smoke test and checks both outcomes.

Run the example and the focused tests from the repository root:

```bash
python -m pip install -e ".[dev]"
python examples/lifecycle_security_demo.py --output /tmp/paca-lifecycle-demo.json
python -m pytest tests/test_lifecycle_communication.py tests/test_lifecycle_demo_cli.py -q
```

## Validation results

The code revision validated by the following runs was `bece5c3f507cac0669c60b778a42b4b456b25d03`. The commits after that revision, up to the current documentation snapshot, changed documentation only.

CI run #1050 (`46156942241`) passed the Python 3.10–3.13 test matrix, Ruff lint and formatting, the core, extended and research installation-profile checks, broker UID isolation, AgentDojo adapter tests, LangGraph integration, PostgreSQL checkpoint integration, wheel smoke tests and Docker build.

Release-validation run #829 (`46156942338`) passed the full test suite, the configured security-critical type checks, lint and formatting, installation-profile checks, broker isolation, and wheel and source-distribution build and smoke tests.

The live AgentDojo benchmark did not run. No `OPENAI_API_KEY` was configured, so its preflight, model run and result upload steps were skipped. The job's successful status does not mean that a live-model experiment was completed.

## What this change does not establish

The new check applies only to operations sent through the configured `PACAAgentRuntime` methods. Direct calls to `HMACCapabilityAuthority.issue()`, `HMACAgentMessageCodec.seal()` or `HMACAgentMessageCodec.open()` still bypass this runtime session check. The same is true for alternate transports, raw framework APIs and direct database access.

Each `LifecycleSecurityController` represents one active principal and session. A multi-agent application therefore needs separate controller/runtime instances for separately authenticated agents, with the host responsible for establishing their session details. The local `completed` audit event means that the adapter call returned. It does not prove that a message reached another machine, that the receiving agent processed it, or that a remote resource committed an effect.

The message codec still uses HMAC for its envelope signature. This change does not add OIDC or workload identity, managed KMS/HSM key custody, a distributed lifecycle transaction or remote-provider commit protection.

The audit digest is useful for matching an event to the data that was processed. It is not encryption and should not be treated as a confidentiality control. Audit records still need suitable access controls and retention. The connected test fixture also uses a permissive memory metadata callback to isolate the session and lineage checks; the repository's separate memory-policy tests remain necessary.

**In summary:** PR #59 connects the existing session check to delegation and message operations on the PACA runtime path. It closes that specific gap, but it does not make every path through an agent, framework, host or provider subject to lifecycle enforcement.
