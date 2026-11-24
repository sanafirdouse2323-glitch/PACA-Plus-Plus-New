# PACA++ Security Semantics — v1.0.0-draft

**Status:** Formalisation target and implementation contract; not a proof of current code  
**Related:** [Architecture Specification](ARCHITECTURE_SPECIFICATION.md), [Protocol Contracts v1.0.0](../contracts/v1.0.0/README.md)

## 1. Security state

The relevant abstract state for a protected operation is:

    S = (I, P, A, Q, E, R, V)

- I: authenticated identity/session state;
- P: information-provenance graph and labels;
- A: authority/delegation graph and grant status;
- Q: usage, quota, replay and idempotency state;
- E: resource/effect state and receipts;
- R: revocation and policy state;
- V: current policy/version and evidence freshness.

An operation is not allowed merely because a policy engine returned allow. Relevant state and bindings must be validated at the enforcement point.

## 2. Authority attenuation

Represent a grant as:

    G = (s, t, k, p, aud, Act, Res, Data, Dest, nb, exp, Bud, Appr, Del, parent)

where s is subject, t tenant, k task, p purpose, aud audience, Act action set, Res resource predicate set, Data data constraints, Dest destinations, nb/exp validity interval, Bud budgets, Appr approval obligations and Del delegation rights.

A child grant C is valid only if:
- C.parent identifies the exact parent grant and the parent digest verifies;
- C.s is an explicitly delegated/authenticated recipient;
- tenant, purpose and task/subtask are within the parent's declared delegation scope;
- C.Act is a subset of P.Act;
- every resource predicate in C.Res is proven semantically contained in the parent resource scope;
- C.Data is at least as restrictive as P.Data;
- C.Dest is a subset of P.Dest;
- C.nb is no earlier than P.nb and C.exp is no later than P.exp;
- child budgets are atomically reserved from the parent's remaining budgets and cannot exceed them; and
- approval and delegation obligations are preserved or strengthened.

String equality, path-prefix tests and glob matching are not a general containment proof. Predicate semantics must be typed and versioned. Unknown predicate types or undecidable containment cause denial.

## 3. Information-flow and declassification rules

Integrity and sensitivity are independent dimensions.

- Integrity ordering: untrusted is less trusted than trusted. The join of derived inputs selects the least-trusted input.
- Sensitivity ordering: public (0), internal (1), confidential (2), restricted (3). The join selects maximum sensitivity.
- Tenant and origin dependencies are unioned. Unknown or mixed ownership is preserved, not collapsed into a single convenient tenant.
- A derivation MUST NOT improve integrity or lower sensitivity without an explicit declassification operation.
- Declassification MAY lower sensitivity only when an authorised, policy-bound transformation records exact input and output digests, principal, destination, purpose, and durable audit evidence.
- Declassification MUST NOT change untrusted integrity to trusted, erase origins, erase parent edges or resolve unknown tenancy without independent authenticated evidence.
- Redaction is a transformation; it does not by itself establish permission to disclose the result.

## 4. Revocation closure

Let Desc(G) be all grants reachable from grant G by following child-to-parent ancestry. Revoking G makes every grant in {G} union Desc(G) inactive for new protected operations and invalidates outstanding permits derived from any member of that set.

Derived information whose lineage contains a revoked/quarantined node is affected. Access is denied until the data is deleted, quarantined or explicitly re-evaluated and re-authorised by a recovery policy. Removing the source record without finding descendants is not revocation closure.

A cached authority result may not supersede a newer revocation epoch. Immediate revocation requires a linearizable check at the effect boundary. Bounded-staleness deployments must state the revocation delay and deny high-consequence effects if status freshness cannot be met.

## 5. Commit state machine

    NEW -> AUTHORISED -> PERMIT_ISSUED -> COMMITTED

Terminal alternatives are DENIED, EXPIRED, REVOKED, CONFLICTED and UNCERTAIN.

A permit binds subject, tenant, task, purpose, action, exact resource, destination, canonical argument digest, payload digest, resource-version precondition, policy epoch, grant identifier, operation identifier, nonce, expiry and idempotency key.

The destination/resource PEP must recheck the active grant, policy epoch, expiry, revocation and quota at commit. Permit consumption and resource mutation must share one atomic commit or a destination-native conditional mutation. If they cannot, the adapter reports a weaker guarantee and enters reconciliation on an uncertain result.

The linearization rule for a serializable atomic commit is:
- If commit linearizes before revocation, it may complete under the authority active at that point.
- If revocation linearizes before commit, the commit must be denied.
- A commit already linearized is not retroactively cancelled by later revocation.
- A retry after timeout is forbidden until the destination outcome is reconciled or an idempotency guarantee makes that retry safe.

## 6. Broker identity and session binding

A worker cannot select its own principal by adding a field to a request. The broker maps an authenticated transport/session to the principal established by a trusted launcher or identity authority. Requests are bound to a fresh nonce, intended audience, session identifier and channel binding. The broker checks replay state and the grant's principal/task/resource scope.

The transport proof is adapter-specific; the semantic requirement is common. An adapter must not claim peer authentication when it only reads an unauthenticated caller-supplied identifier.

## 7. Formal model coverage

The initial broker TLA+ model is intended to exercise permit/request binding, one-use permit consumption, revocation and policy-epoch invalidation, single-operation quota, pre-disclosure authorisation, and serialised commit/revocation interleavings.

It does not yet model cryptographic algorithms, real clocks, distributed consensus, all resource predicate languages, multi-provider transactions or refinement of Python implementations. Those remain separate proof and test obligations.