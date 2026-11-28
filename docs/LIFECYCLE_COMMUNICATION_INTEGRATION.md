# Lifecycle communication and delegation integration

**Repository:** `PACA-Plus-Plus-New` only.  
**Change:** session-bound delegation and inter-agent message operations in `PACAAgentRuntime`.  
**Implementation branch:** `research/lifecycle-session-communication-2026-11-28`.  
**Status:** implemented on the PR research branch; CI run #1050 and release-validation run #829 passed for the code revision. Not merged to `main` and not independently security-reviewed.

## Problem addressed

The original lifecycle controller bound effect requests to one active session, but `PACAAgentRuntime.delegate()`, `send_message()` and `receive_message()` invoked their authority/message adapters without applying that session binding. The adapters had their own authority, envelope, provenance, revocation and replay checks, but those checks did not prove that the operation belonged to the active orchestrator session.

This left a continuity gap: a valid capability belonging to a different principal or task could be presented to a runtime instance whose lifecycle controller represented another session.

## Change

When `lifecycle_security` is configured:

1. **Delegation:** the runtime verifies the parent capability, requires immutable authority lineage, hashes a canonical delegation-intent record (including child tool pins), and routes issuance through the internal lifecycle transition helper. The context must match the active principal, tenant, task, purpose and policy epoch. `PACAAgentRuntime.delegate()` now exposes the issuer's existing `tool_pins` option so the child can receive only an implementation digest already pinned by its parent. The authority issuer remains responsible for parent delegation scope, child grant attenuation, expiry, tool-pin attenuation, call/fan-out quotas and authenticated child identity.
2. **Message send:** the runtime verifies the sender capability and authority lineage, computes a digest over the typed payload value and its provenance label/references, and routes the signed-envelope operation through the active session check. The message codec remains responsible for send-recipient scope, memory access, lineage integrity, revocation and envelope authentication.
3. **Message receive:** the runtime verifies the recipient capability and lineage, binds it to the active recipient session, and only then invokes the message codec. Thus a session mismatch is rejected before the codec consumes the durable message receipt or memory-read budget. The codec remains responsible for signature verification, sender/recipient grants, replay receipt, provenance and memory authorization.
4. **Stop/session serialization:** the trusted adapter callback executes while the lifecycle controller lock is held. A concurrent `stop()` or `close_session()` therefore cannot pass the context check and change the local session before the routed adapter operation completes.
5. **Audit minimisation and re-entry:** transition events record phase, operation, session metadata, subject and SHA-256 digest. They do not contain message payload bytes or raw token values. Because the configured audit sink is trusted host code and may be invoked synchronously, the controller rechecks that the active session has not been stopped or replaced by a reentrant audit callback before dispatching the adapter operation.

The controller accepts only the explicit transition pairs `delegation/delegate` and `message/send|receive`. The helper is an internal PACA runtime primitive, not an application authorisation API. Its callback is a trusted PACA-owned adapter operation; model- or user-supplied callbacks must never be passed to it.

## Validation record

- **CI run #1050** (`46156942241`): Python 3.10–3.13, Ruff lint/format, all three installation-profile security contracts, broker UID isolation, AgentDojo adapter, LangGraph, PostgreSQL checkpoint integration, wheel smoke test and Docker build completed successfully.
- **Release-validation run #829** (`46156942338`): complete test suite, configured security-critical type checks, lint/format, installation-profile contracts, broker isolation, wheel/source-distribution build and smoke tests completed successfully.
- The `agentdojo-real-benchmark` job in CI #1050 ended successfully with its credential-dependent preflight, live model run and upload steps **skipped** because `OPENAI_API_KEY` was not configured. No live-model result is claimed.
- The validated code head for these runs was `bece5c3f507cac0669c60b778a42b4b456b25d03`. Subsequent branch commits through the current documentation snapshot were documentation-only. No independent security review has been completed.

## Regression tests

`examples/lifecycle_security_demo.py` is a standalone deterministic two-scenario offline run. `tests/test_lifecycle_demo_cli.py` executes it as a smoke test, checks the benign commit receipt fields and verifies that the poisoned scenario has no sink row. `tests/test_lifecycle_communication.py` adds isolated tests for:

- rejecting delegation when the parent capability principal differs from the active lifecycle principal;
- recording a successfully issued, attenuated child capability as a session-bound delegation;
- recording a successful message-send transition without writing payload text into the audit stream;
- rejecting a sender capability outside the active session;
- rejecting a recipient-session mismatch before message receipt consumption, followed by successful delivery through the correct recipient session; and
- rejecting message operations after the lifecycle kill switch has stopped the controller.

These tests complement, rather than replace, the existing durable-message tests for signature verification, provenance checks, replay receipts, authority revocation and concurrent receipt consumption.

## Connected deterministic trajectory

The added tests also exercise a single local reference trajectory rather than only isolated method calls:

1. A fixed-identity connector captures either an explicitly trusted test source or an untrusted external-content source with versioned lineage.
2. The sender retrieves the source through `TrustedMemoryAdapter` and records input, retrieval and a model-independent candidate-plan audit digest. The plan is an explicit test fixture; no hidden model reasoning is claimed.
3. The sender delegates an attenuated child capability to `worker-b`, including the parent-pinned `write_file` implementation digest.
4. The sender seals the lineage-bearing payload; a separate recipient session validates and opens the message.
5. The recipient submits the exact received value to `PACAAgentRuntime.execute_effect()` with the concrete SQLite fenced-resource executor and the packaged `Monitor`.
6. The benign control writes a row whose version, child authority ID, request digest and commit nonce are checked in the actual resource registry. The poisoned-memory control is denied by lifecycle integrity policy and asserts that no sink row or successful lifecycle commit event exists.

This provides an executable integration demonstration for a declared local reference path, including a positive-utility control and a protected-sink negative case. It does not represent a live LLM, hidden planning, a production connector, an arbitrary host filesystem, a remote SaaS provider or universal six-stage mediation. The deterministic plan and connectors are test fixtures; trust comes from the host-configured adapter labels, not from the model's assertion.

## Security boundary and limitations

This change improves lifecycle continuity only for operations routed through the configured `PACAAgentRuntime`. It does not make the Python object boundary a host security boundary. Direct calls to `HMACCapabilityAuthority.issue()`, `HMACAgentMessageCodec.seal()` or `HMACAgentMessageCodec.open()`, alternate transports, raw framework APIs and direct database access can still bypass the runtime session gate.

The SHA-256 audit digest is a correlation/integrity reference, not encryption or a confidentiality guarantee; treat audit records as sensitive and restrict access. The integration test fixture uses a permissive memory metadata callback to isolate the session/lineage path, so it does not replace the repository's dedicated memory-policy and adapter tests.

Each `LifecycleSecurityController` represents one active session/principal. Multi-agent deployments must use distinct controller/runtime instances whose session data is established by trusted host identity/session code. A local `completed` event means the local adapter call returned; it is not proof of network delivery, remote processing or destination-side effect commitment.

The message codec currently uses HMAC for its envelope signature. This work does not change its key-custody or distributed key-management assumptions, nor does it add production OIDC/workload identity, KMS/HSM custody or a distributed lifecycle transaction.

## Validation required

Before describing this change as validated, require:

- the lifecycle session-binding tests, the benign/poisoned connected trajectory tests and the reentrant-audit test to pass;
- the complete Python test matrix and repository lint/type checks to pass;
- durable lifecycle/message and PostgreSQL-backed authority integration tests to pass; and
- review of the branch diff to confirm that no existing adapter checks or replay/usage semantics were weakened.

A successful CI run validates the repository test suite for the branch; it does not establish complete lifecycle mediation, live multi-agent effectiveness, production readiness or independent security assurance.
