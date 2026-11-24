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
8. The current reference broker supports only logical-file read/write operations. Logical-file writes require a one-use commit permit, exact JCS payload digest, resource-version precondition and non-empty provenance references; unsupported delete/send/execute operations are denied. A read/query requires a grant and authorisation before bytes are released.
9. A commit permit is consumed once. Consumption and mutation must be atomic where the destination supports it; otherwise the result must be labelled with the actual weaker/uncertain semantics and reconciled.
10. The broker obtains caller identity from its authenticated channel/session state; it does not accept identity from the request body.
11. Isolation capability claims are accepted only with verified deployment evidence. operator_assertion is not sufficient for a conformance profile that requires isolation.
12. Audit records refer to digests and evidence identifiers rather than leaking credentials or full sensitive payloads.

## 7. Resource predicate semantics

The schema represents predicates as typed values; it does not define universal path/URL/provider matching semantics. Each predicate type must have a versioned semantics definition and a containment decision procedure. If a procedure cannot prove that child scope is contained in parent scope, delegation is denied. Adapters cannot invent new predicate semantics at runtime.

## 8. Error and failure semantics

Implementations should expose typed outcomes at the API boundary: invalid_message, unauthenticated, identity_mismatch, policy_denied, grant_expired, grant_revoked, stale_policy, provenance_invalid, scope_unproven, quota_exceeded, replay_detected, commit_conflict, resource_unavailable, outcome_uncertain and internal_error.

Security-critical dependency failure defaults to denial. A timeout after a remote mutation request may have reached the provider is outcome_uncertain, not resource_unavailable and not permission to retry blindly.

## 9. Limits

This contract bundle is a schema and design artefact. It does not yet provide a production encoder/verifier, authenticated broker session, identity provider, resource adapter, remote provider commit protocol or independent interoperability test suite.

## 10. Reference-core primitives

The `paca.contracts` package provides strict JSON parsing, RFC 8785 canonical UTF-8 bytes, domain-separated SHA-256 object digests and optional schema validation. Install the `protocol` extra to enable these helpers. The package does not verify signatures, establish the authenticated broker session, evaluate authority, check revocation or perform protected resource operations.

Canonical JSON input rejects duplicate object member names, non-JSON constants, invalid UTF-8, unpaired Unicode surrogates and integer values outside the I-JSON exact integer range. Exact large integer values must be encoded as decimal strings. Unicode strings are not normalised.

The `validate_message` function checks only the versioned JSON Schema. A structurally valid proof field remains unverified until a future trusted key-verification service validates it against authenticated issuer, message type and audience configuration.

## 11. Ed25519 message signing and verification

The reference core exposes `MessageSigner` and `MessageVerifier` in `paca.contracts.signatures`. The signer accepts an Ed25519 private key, key ID, issuer and permitted audiences. The verifier accepts a trusted key ring whose entries bind each public key to one issuer, an explicit audience set and an explicit message-type set.

Signed bytes are:

    UTF8("PACA++/MESSAGE/V1\\n" + message_type + "\\n") || JCS(message_without_proof)

The proof is Ed25519 with unpadded base64url encoding. The verifier accepts only Ed25519, checks issuer/audience/type against trusted local configuration, removes the proof field and verifies the exact canonical content. A message cannot select a different algorithm by changing its proof field.

Key generation, private-key custody, public-key distribution, rotation, compromise handling and issuer authorization remain deployment responsibilities. The verifier authenticates the configured message issuer/key scope; it does not independently prove that a user, agent or workload identity claim inside the message is true. That requires an authenticated identity authority or a transport/session binding.

Schema validation and signature verification are separate operations. A caller should validate shape and verify the signature before using a message; neither step replaces the broker's current grant, revocation, quota or resource-boundary checks.

## 12. Broker operation-intent digest

For `paca.broker-operation.v1`, compute the permit request digest from the complete message object after removing exactly `proof` and `commit_permit_ref`, then apply the `request` digest domain. All other fields, including operation ID, session ID, nonce, resource and version, authority grant reference, payload, provenance references, payload digest and idempotency key, remain bound.

The worker's Ed25519 signature covers the full message including `commit_permit_ref`. The commit permit is separately signed by the capability issuer and binds the operation-intent digest and payload digest. The broker verifies both signatures and all cross-bindings. A permit reference cannot be swapped without invalidating the worker signature.
