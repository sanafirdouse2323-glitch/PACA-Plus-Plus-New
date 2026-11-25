# PACA++ Protocol Contracts — v1.0.0

**Status:** Initial versioned contract draft  
**Schema:** contracts/v1.0.0/paca-contracts.schema.json  
**Applies to:** PACA-Plus-Plus-New architecture proposal only

## 1. Scope

This directory defines the first versioned, platform-neutral wire/data contracts for identity context, provenance evidence, policy requests and responses, authorisation grants, PEP invocations, commit permits, broker operations, isolation profiles and audit events.

The JSON Schema validates structure and basic types. It does not prove a signature, authenticate a peer, validate a resource predicate, check revocation state, enforce quotas, establish transaction atomicity or prove that an adapter really isolates a worker. Those are runtime semantics and require separate tests.

## 2. Versioning

The protocol version is 1.0.0. Each message carries contract_version and a type-specific message_type. Breaking semantic or wire changes require a new major version. Compatible additive message types or optional fields require a minor version. Non-semantic corrections require a patch version.

Security-sensitive consumers MUST reject unknown major versions and MUST NOT silently downgrade to a weaker interpretation. The schema uses closed objects (additionalProperties: false) for security envelopes.

## 3. Authentication and identity binding

A message proof contains a key identifier, algorithm identifier and base64url signature. The verifier MUST select accepted algorithms and key material from trusted local configuration; it MUST NOT trust the message's algorithm field to enable an otherwise disallowed algorithm. Signatures cover the canonical message with the proof member excluded, using this domain separator:

    PACA++/MESSAGE/V1\\n{message_type}\\n

The identity-context payload is evidence, not self-authenticating identity. Its issuer, subject and audience must be verified against the configured identity authority.

For broker operations, the broker MUST derive the caller principal from an authenticated session/channel established out of band. The worker message deliberately has no caller-supplied principal field. A session_id alone is not proof: the broker must verify the session, channel binding, request nonce, audience and identity-to-task binding.

## 4. Canonicalisation and digests

Implementations MUST use the JSON Canonicalization Scheme (JCS), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), for JSON objects included in a signature or digest. RFC 8785 is an Informational RFC, not an Internet Standards Track specification; PACA++ adopts its serialization rules as a protocol requirement for interoperability.

Input must be valid UTF-8 JSON adapted to the I-JSON subset: duplicate object member names and invalid Unicode are rejected; JSON numbers must be representable as IEEE 754 binary64 values. Security-relevant counters/identifiers requiring larger exact integer ranges should be encoded as decimal strings. Strings are not Unicode-normalized during canonicalisation.

Digest construction is domain-separated. For a structured object:

    SHA-256(UTF8("PACA++/DIGEST/V1\\n" + purpose + "\\n") || JCS(object))

The purpose string is a fixed, protocol-defined identifier such as request, payload, provenance, grant, policy-decision or audit-event. The same bytes in different semantic contexts therefore have different digests. Do not hash pretty-printed JSON, ordinary language-native JSON serialization, or a transport representation unless it is exactly the canonical JCS representation.

A resource's version identifier or provider ETag is not automatically a content digest. Record each separately.

## 5. Messages

| Message type | Direction | Security purpose |
|---|---|---|
| paca.identity-context.v1 | Identity authority → PACA++ | Authenticated subject/workload, tenant, task and purpose context |
| paca.provenance-evidence.v1 | Trusted capture adapter → PACA++ | Versioned information lineage and conservative labels |
| paca.policy-evaluation.request.v1 | Core/PEP → PDP | Canonical, typed policy input |
| paca.policy-evaluation.response.v1 | PDP → core/PEP | Policy decision and obligations; not a grant |
| paca.authorization-grant.v1 | Authority service → PEP/broker | Scoped, authenticated grant and delegation lineage |
| paca.pep-invocation.v1 | Runtime → PEP | One exact lifecycle operation to mediate |
| paca.commit-permit.v1 | Authority service → resource PEP/broker | Short-lived, one-use mutation authorisation |
| paca.broker-operation.v1 | Authenticated worker session → broker | Narrow resource operation |
| paca.isolation-profile.v1 | Approved isolation adapter → supervisor | Declared and evidenced isolation capabilities |
| paca.audit-event.v1 | Trusted component → audit sink | Structured decision, resource, commit and recovery evidence |

## 6. Cross-field semantic requirements

JSON Schema alone cannot establish the following. Every implementation MUST enforce them before performing a protected operation:

1. The signature verifies over the exact canonical message and its domain separator; the key is trusted for this issuer, message type and audience.
2. created_at, expiry and validity intervals are checked against a trusted clock with a documented skew policy.
3. The authenticated session's subject, workload, tenant, task, purpose and audience match the grant and request. Never trust worker-supplied principal claims.
4. the broker operation intent digest is recomputed from the canonical broker message after removing only proof and commit_permit_ref. It binds the operation ID, session, nonce, operation, exact resource/version, grant reference, payload and provenance evidence. The message signature still covers commit_permit_ref. This avoids a circular dependency when a commit permit is issued for the intent and then referenced by the signed request.
5. Provenance references resolve to existing immutable object versions and their recorded digests/lineage. Missing or stale security-critical evidence denies the operation.
6. The grant is active, not revoked or expired, is at the current policy epoch, contains the exact action/resource/destination, and has sufficient remaining budget.
7. Delegation containment is proven using typed predicate semantics; string-prefix or glob heuristics are insufficient.
8. The PR branch now contains two deliberately narrow in-process protocol adapters, not a general broker service. `InProcessBrokerReadMediator` verifies a signed v1.0.0 `read` operation and mediates bounded reads of local logical `file` resources through the transactional registry. It requires a trusted provenance-release decision before disclosing content. `InProcessBrokerWriteMediator` verifies a signed v1.0.0 `write` operation and a separately signed `paca.commit-permit.v1`, binds the permit to the exact broker intent, subject kind/ID, grant, tenant, task, purpose, destination, resource/version, payload digest, policy epoch and idempotency key, and calls the SQLite/PostgreSQL fenced resource transaction. The local write profile accepts only logical file resources and the `write_file` action; its trusted provenance callback must resolve and verify the signed provenance references and return bounded metadata. The schema-v7 registry consumes permit ID, permit nonce, broker receipt and resource mutation transactionally; an exact retry returns the original committed result without a second mutation or quota charge, while a newly issued replacement permit for the same exact operation is itself recorded as consumed. Neither adapter authenticates network transport or creates a separate process/IPC boundary. The write adapter does not perform host filesystem writes or remote-provider mutations. The read adapter does not implement query, field projection or version-selector semantics. Delete, send and execute remain unsupported. Registry byte ceilings, signatures and grant checks do not substitute for provenance authenticity, lineage, sensitivity or release/declassification policy; those remain trusted adapter responsibilities and require independent validation.
9. A commit permit is consumed once. Consumption and mutation must be atomic where the destination supports it; otherwise the result must be labelled with the actual weaker/uncertain semantics and reconciled.
10. The broker obtains caller identity from its authenticated channel/session state; it does not accept identity from the request body.
11. Isolation capability claims are accepted only with verified deployment evidence. operator_assertion is not sufficient for a conformance profile that requires isolation.
12. Audit records refer to digests and evidence identifiers rather than leaking credentials or full sensitive payloads.

## 6.1 Broker operation structural requirements

The v1.0.0 schema enforces a common operation envelope with an authenticated session reference, channel-binding digest, request nonce, resource reference and authorization-grant reference.

| Operation | Required operation-specific fields |
|---|---|
| read | Bounded `read_constraints.max_bytes`; no commit permit |
| query | Bounded `read_constraints.max_bytes`; no commit permit |
| write | Commit permit, idempotency key, payload digest, payload, at least one provenance reference, and resource version |
| delete | Commit permit, idempotency key, payload digest, at least one provenance reference, and resource version |
| send | Commit permit, idempotency key, payload digest, payload, and at least one provenance reference |
| execute | Commit permit, idempotency key, payload digest, payload, and at least one provenance reference |

A digest does not replace the payload where an operation needs a structured body. A deletion is represented by its exact resource/version and a digest of the canonical deletion intent; it does not require a separate body object. These schema requirements validate message shape only; a trusted implementation must still recompute the digests and resolve the evidence before effect.

## 7. Resource predicate semantics

The schema represents predicates as typed values; it does not define universal path/URL/provider matching semantics. Each predicate type must have a versioned semantics definition and a containment decision procedure. If a procedure cannot prove that child scope is contained in parent scope, delegation is denied. Adapters cannot invent new predicate semantics at runtime.

## 8. Error and failure semantics

Implementations should expose typed outcomes at the API boundary: invalid_message, unauthenticated, identity_mismatch, policy_denied, grant_expired, grant_revoked, stale_policy, provenance_invalid, scope_unproven, quota_exceeded, replay_detected, commit_conflict, resource_unavailable, outcome_uncertain and internal_error.

Security-critical dependency failure defaults to denial. A timeout after a remote mutation request may have reached the provider is outcome_uncertain, not resource_unavailable and not permission to retry blindly.

## 9. Limits

This contract bundle is a schema and design artefact. It does not yet provide a production encoder/verifier, authenticated broker session, identity provider, resource adapter, remote provider commit protocol or independent interoperability test suite.

## 10. Reference-core primitives

The `paca.contracts` package provides strict JSON parsing, RFC 8785 canonical UTF-8 bytes, domain-separated SHA-256 object digests and optional schema validation. The same package also exposes a reference Ed25519 message signer and verifier (`MessageSigner`, `MessageVerifier` and `TrustedMessageKey`) with explicit key-ID, issuer, audience and message-type scoping. Install the `protocol` extra to enable these helpers. These primitives do not establish an authenticated broker session, prove a worker's real-world identity, evaluate authority, check revocation or perform protected resource operations.

Canonical JSON input rejects duplicate object member names, non-JSON constants, invalid UTF-8, unpaired Unicode surrogates and integer values outside the I-JSON exact integer range. Exact large integer values must be encoded as decimal strings. Unicode strings are not normalised.

The `validate_message` function checks only the versioned JSON Schema and does not invoke signature verification. A caller that requires message authentication must separately use a configured `MessageVerifier` with trusted public keys and explicit issuer, audience and message-type scopes. Structural validation and signature verification are separate operations; neither proves the truth of a user, agent or workload identity claim without an authenticated identity authority or transport/session binding.

## 11. Ed25519 message signing and verification

The reference core exposes `MessageSigner` and `MessageVerifier` in `paca.contracts.signatures`. The signer accepts an Ed25519 private key, key ID, issuer and permitted audiences. The verifier accepts a trusted key ring whose entries bind each public key to one issuer, an explicit audience set and an explicit message-type set.

Signed bytes are:

    UTF8("PACA++/MESSAGE/V1\\n" + message_type + "\\n" + key_id + "\\n") || JCS(message_without_proof)

The proof is Ed25519 with unpadded base64url encoding. The verifier accepts only Ed25519, checks issuer/audience/type against trusted local configuration, removes the proof field and verifies the exact canonical content. A message cannot select a different algorithm by changing its proof field.

Key generation, private-key custody, public-key distribution, rotation, compromise handling and issuer authorization remain deployment responsibilities. The verifier authenticates the configured message issuer/key scope; it does not independently prove that a user, agent or workload identity claim inside the message is true. That requires an authenticated identity authority or a transport/session binding.

Schema validation and signature verification are separate operations. A caller should validate shape and verify the signature before using a message; neither step replaces the broker's current grant, revocation, quota or resource-boundary checks.

## 12. Broker operation-intent digest

For `paca.broker-operation.v1`, compute the permit request digest from the complete message object after removing exactly `proof` and `commit_permit_ref`, then apply the `request` digest domain. All other fields, including operation ID, session ID, nonce, resource and version, authority grant reference, payload, provenance references, payload digest and idempotency key, remain bound.

The worker's Ed25519 signature covers the full message including `commit_permit_ref`. The commit permit is separately signed by the capability issuer and binds the operation-intent digest and payload digest. The broker verifies both signatures and all cross-bindings. A permit reference cannot be swapped without invalidating the worker signature.

## 13. Reference broker-operation verifier

The reference core now exposes `BrokerSessionContext`, `BrokerOperationVerifier` and `VerifiedBrokerOperation` from `paca.contracts`. The verifier performs the following checks on a v1.0.0 broker-operation message:

1. Takes a detached canonical JSON/I-JSON snapshot before verification, so subsequent semantic checks do not read a caller-mutable mapping.
2. Validates the closed v1.0.0 broker-operation schema.
3. Verifies the Ed25519 proof against the configured issuer, key ID, audience and message-type key scope.
4. Requires the signing issuer/key ID, audience, session ID and channel-binding digest to match the supplied session context.
5. Requires the request's grant reference to match the grant reference resolved by the caller.
6. Recomputes the request-intent digest after removing exactly `proof` and `commit_permit_ref`.
7. Recomputes the domain-separated payload digest when a payload is present.
8. Enforces signed-message freshness and configured canonical-message/requested-read-size ceilings. The default maximum message age is 300 seconds with 30 seconds of allowed future clock skew; both settings are configurable within bounded limits. The size defaults are 1 MiB each; configured ceilings cannot exceed 16 MiB per message or 64 MiB per requested read.
9. Derives the registry-compatible nonce digest and exposes an access-receipt builder for the existing transactional resource registry. The verified result also retains the detached canonical signed message bytes for downstream trusted mediation.

`BrokerSessionContext` is a trusted hand-off value, not an authentication mechanism. A transport adapter must authenticate the peer and derive the channel-binding digest from the live transport before constructing it. Principal, workload, tenant, task and purpose values must come from that trusted session/identity context, never from the worker's broker-operation body.

A network adapter MUST also enforce a raw transport-body/frame size limit before JSON decoding. The verifier receives an already-materialised mapping, so its canonical-message limit does not replace an ingress-level allocation limit.

The verifier is intentionally stateless and does not:
- establish or authenticate a network connection or worker session;
- persist or atomically consume request nonces or idempotency keys (the receipt builder only constructs data; the registry must insert it transactionally with the resource operation);
- resolve a grant, check its current status, delegation chain, policy epoch, scope or quota;
- resolve or release provenance evidence;
- authenticate or consume a commit permit;
- enforce `read_constraints.max_bytes` against the actual returned resource bytes (the verifier checks the requested bound, but the resource adapter must enforce it on the result);
- access a database, filesystem, memory store or external provider; or
- execute a broker operation.

For `delete`, the schema carries a digest of the canonical deletion intent but no payload object; the verifier therefore preserves that digest for later comparison with the separately authenticated commit permit rather than pretending it can recompute it. The verifier returns immutable structured request facts together with the detached canonical signed message bytes. A caller MUST NOT treat `VerifiedBrokerOperation` as an authorization decision or permit resource access based on it alone.

This increment is a protocol-verification primitive, not the broker process/IPC boundary. A production-facing ingress still needs authenticated transport/session establishment, authoritative grant and provenance checks, persistent replay protection, a resource PEP, commit-time revalidation, bounded read disclosure and adversarial bypass tests.



## 14. Legacy authority-registry integration boundary

The existing local authority registry uses `AuthorityLineage` records rather than the v1.0.0 `authorization-grant` message as its persisted grant format. Newly issued legacy capabilities now include the immutable per-capability `max_calls` value and grant audience in their stored authority record; registry effect, message, read and commit operations cap caller-supplied limits against that stored ceiling. Delegated records cannot exceed a persisted parent's ceiling or change its audience.

Historical authority records without `max_calls` or `audience` remain readable and verifiable without changing their canonical bytes or parent-chain digests. Their historical per-capability ceiling and grant audience are not reconstructed from an untrusted broker request. A broker resolver MUST fail closed when the referenced record omits either field. These additive record fields do not implement the v1.0.0 grant schema, typed protocol predicates, protocol grant usage-limit counters, OIDC identity, or protocol commit-permit verification.

## 15. In-process broker read mediator

The PR branch includes `InProcessBrokerReadMediator` as a narrow integration of the v1.0.0 signed broker-operation verifier with the existing local authority registry. It accepts only `operation=read` for `resource_type=file`. It resolves the referenced active `AuthorityLineage`, requires matching trusted grant issuer/audience and session principal/tenant/task/purpose, requires persisted `max_calls`, and passes the signed nonce receipt and `read_constraints.max_bytes` into the registry's transactional read method. The registry enforces active authority, the `read_file` grant, principal binding, per-capability and task quotas, replay uniqueness and the complete serialized response-byte ceiling.

A mandatory trusted provenance-release callback must approve the returned resource and its recorded provenance metadata before any content is returned to the caller. A failed or unavailable release decision denies disclosure; because the registry read has already committed, its replay receipt and quota remain consumed. The callback and its provenance/policy sources are part of the trusted computing base and require independent validation.

This read mediator is in-process only. It does not authenticate transport or construct `BrokerSessionContext`; a trusted ingress must do that. It rejects writes, deletes, queries, sends, execution, remote-provider resources, version selectors and field projections. Write mediation is implemented separately by `InProcessBrokerWriteMediator` in `paca.broker_write`; see Section 16. Neither adapter claims a broker process, IPC boundary or complete resource mediation.


## 16. In-process protocol commit and local file-write mediator

The PR branch includes `InProcessBrokerWriteMediator` in `paca.broker_write`. It accepts one local profile only: a signed `operation=write` for `resource_type=file`, a canonical decimal logical resource version precondition, an object payload with a verified SHA-256 digest, one or more provenance references, a signed broker idempotency key equal to the broker operation ID, and a separately signed v1.0.0 `commit-permit`.

The permit is verified by `ProtocolCommitPermitVerifier` against a separately configured Ed25519 keyring, issuer and PEP audience. The adapter then binds the verified permit to the exact broker request intent, payload digest, permit ID/reference, operation ID, trusted session subject kind and ID, immutable grant ID and audience, tenant, task, purpose, action, destination, resource object/version, current policy epoch and idempotency key. The permit must be single-use and within the configured lifetime/freshness window. A trusted permit resolver supplies the signed permit envelope; a trusted provenance callback must resolve the immutable provenance references, validate their digests/lineage/policy, and return bounded metadata for persistence. These callbacks are part of the trusted computing base and are not authenticated merely by being Python callables.

Authority schema version 7 adds unique permit-ID and tenant/task-scoped idempotency indexes to the existing resource-commit receipt table. The permit nonce, permit ID, request/payload digests, idempotency key, resulting resource version, broker access receipt, quota charge and local resource mutation are handled under the same SQLite transaction or PostgreSQL single-primary transaction. Exact retries reconcile the already committed result instead of repeating the effect or quota charge. A replacement permit for the same exact operation is separately recorded as consumed; attempts to repurpose a consumed permit or an idempotency key for different request bytes fail closed.

This remains an in-process local logical-resource adapter, not an authenticated broker process or IPC boundary. It does not write to host filesystem paths, call remote providers, implement delete/query/send/execute, or prove that other framework/executor paths cannot bypass it. PostgreSQL serialization applies only to cooperating clients using the same authoritative primary; it is not multi-primary consensus, rollback-safe failover or a distributed lifecycle store.