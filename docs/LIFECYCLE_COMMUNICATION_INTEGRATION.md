# Lifecycle communication and delegation integration

**Repository:** `PACA-Plus-Plus-New` only.  
**Change:** session-bound delegation and inter-agent message operations in `PACAAgentRuntime`.  
**Implementation branch:** `research/lifecycle-session-communication-2026-11-28`.  
**Status:** implementation candidate; CI and review evidence must be checked before treating this change as validated.

## Problem addressed

The original lifecycle controller bound effect requests to one active session, but `PACAAgentRuntime.delegate()`, `send_message()` and `receive_message()` invoked their authority/message adapters without applying that session binding. The adapters had their own authority, envelope, provenance, revocation and replay checks, but those checks did not prove that the operation belonged to the active orchestrator session.

This left a continuity gap: a valid capability belonging to a different principal or task could be presented to a runtime instance whose lifecycle controller represented another session.

## Change

When `lifecycle_security` is configured:

1. **Delegation:** the runtime verifies the parent capability, requires immutable authority lineage, hashes a canonical delegation-intent record, and routes issuance through a lifecycle context transition. The context must match the active principal, tenant, task, purpose and policy epoch. The authority issuer remains responsible for parent delegation scope, child grant attenuation, expiry, call/fan-out quotas and authenticated child identity.
2. **Message send:** the runtime verifies the sender capability and authority lineage, computes a digest over the typed payload value and its provenance label/references, and routes the signed-envelope operation through the active session check. The message codec remains responsible for send-recipient scope, memory access, lineage integrity, revocation and envelope authentication.
3. **Message receive:** the runtime verifies the recipient capability and lineage, binds it to the active recipient session, and only then invokes the message codec. Thus a session mismatch is rejected before the codec consumes the durable message receipt or memory-read budget. The codec remains responsible for signature verification, sender/recipient grants, replay receipt, provenance and memory authorization.
4. **Stop/session serialization:** the trusted adapter callback executes while the lifecycle controller lock is held. A concurrent `stop()` or `close_session()` therefore cannot pass the context check and change the local session before the routed adapter operation completes.
5. **Audit minimisation:** transition events record phase, operation, session metadata, subject and SHA-256 digest. They do not contain message payload bytes or raw token values.

The controller accepts only the explicit transition pairs `delegation/delegate` and `message/send|receive`. The callback is a trusted PACA-owned adapter operation; model- or user-supplied callbacks must never be passed to this API.

## Regression tests

`tests/test_lifecycle_communication.py` adds isolated tests for:

- rejecting delegation when the parent capability principal differs from the active lifecycle principal;
- recording a successfully issued, attenuated child capability as a session-bound delegation;
- recording a successful message-send transition without writing payload text into the audit stream;
- rejecting a sender capability outside the active session;
- rejecting a recipient-session mismatch before message receipt consumption, followed by successful delivery through the correct recipient session; and
- rejecting message operations after the lifecycle kill switch has stopped the controller.

These tests complement, rather than replace, the existing durable-message tests for signature verification, provenance checks, replay receipts, authority revocation and concurrent receipt consumption.

## Security boundary and limitations

This change improves lifecycle continuity only for operations routed through the configured `PACAAgentRuntime`. It does not make the Python object boundary a host security boundary. Direct calls to `HMACCapabilityAuthority.issue()`, `HMACAgentMessageCodec.seal()` or `HMACAgentMessageCodec.open()`, alternate transports, raw framework APIs and direct database access can still bypass the runtime session gate.

Each `LifecycleSecurityController` represents one active session/principal. Multi-agent deployments must use distinct controller/runtime instances whose session data is established by trusted host identity/session code. A local `completed` event means the local adapter call returned; it is not proof of network delivery, remote processing or destination-side effect commitment.

The message codec currently uses HMAC for its envelope signature. This work does not change its key-custody or distributed key-management assumptions, nor does it add production OIDC/workload identity, KMS/HSM custody or a distributed lifecycle transaction.

## Validation required

Before describing this change as validated, require:

- the new lifecycle communication tests to pass;
- the complete Python test matrix and repository lint/type checks to pass;
- durable lifecycle/message and PostgreSQL-backed authority integration tests to pass; and
- review of the branch diff to confirm that no existing adapter checks or replay/usage semantics were weakened.

A successful CI run validates the repository test suite for the branch; it does not establish complete lifecycle mediation, live multi-agent effectiveness, production readiness or independent security assurance.
