# Separate local broker process (Linux)

**Status:** implemented transport adapter and tests; not a production certification.  
**Scope:** PACA-Plus-Plus-New only.

The paca.unix_broker module adds a narrow Unix-domain-socket boundary around the
existing local broker mediators. It is intended for a deployment where the worker
and broker run as different operating-system users and the protected resource state
is accessible only to the broker.

## Process model

- Run the broker under a dedicated OS identity. Keep resource-store access and
  provider credentials in that process.
- Run each worker under a dedicated, unprivileged UID. Do not give the worker direct
  filesystem, database or provider credentials for resources that are meant to be
  protected.
- Put the socket in an existing broker-owned directory owned by the broker UID. Its
  path must contain no symlink components, and the directory must not be group- or
  world-writable.
  Use mode 0600 for one UID or 0660 with a dedicated group. Do not put it in a
  shared writable temporary directory.
- Configure PeerBinding from trusted deployment configuration. The server uses
  Linux SO_PEERCRED to map the connecting UID and optional primary GID to a fixed
  principal, workload, tenant, task and purpose. Unknown identities are rejected.
- Configure the worker UnixDomainBrokerClient with expected_server_uid. The
  client also checks the broker kernel-reported UID before accepting the session.
- Each connection receives a fresh session and channel-binding digest. A connection
  carries one operation only. The existing broker mediator verifies the Ed25519
  operation signature and performs the existing authority, provenance, replay and
  local commit checks.
- Use BrokerMediatorDispatcher to expose only the mediators actually configured.

A deployment must supply the existing read/write mediator instances, trusted
verification key rings, authority registry and provenance callbacks. PeerBinding is
not an identity provider and does not issue cryptographic credentials. It is a
trusted mapping from kernel-authenticated local process credentials to configured
PACA identity fields.

## Supported profile

The transport accepts only read and write. The existing in-process mediators then
narrow those operations further to local logical-file reads and writes. The write
path requires its separately signed commit permit and local registry transaction.
Unsupported operations fail closed.

## Security boundary and non-claims

This adapter is not universal complete mediation. It protects only operations that
are sent through this socket. It does not stop a worker from using another resource
client, subprocess, framework tool, raw database connection or direct host path.
The OS/container policy must independently make protected resources inaccessible
to workers except through the broker. This implementation does not configure that
policy.

It is Linux-specific (SO_PEERCRED) and local-host only. It does not provide a remote
network broker, mTLS, service discovery, high availability, multi-primary
consistency, KMS/HSM-backed key custody, automated key rotation, OAuth/OIDC
identity federation, or production secret distribution.

It does not add remote provider mutations or destination-side commit fencing. The
provider connectors remain read-only. No claim is made that every consequential
resource in a host or SaaS tenant is mediated.

The transport session binds the configured worker identity to the local process
credentials and a fresh connection. It does not establish the truth of model-supplied
identity claims. Ed25519 request verification still depends on a correctly managed
trusted key ring. Private-key generation, storage, rotation, revocation and
authenticated distribution remain separate deployment controls.

The current provenance implementation propagates declared lineage and conservatively
downgrades generated content. It cannot infer every latent semantic dependency in
arbitrary model output. This socket transport does not change that limitation.

## Minimal construction pattern

The service entrypoint should construct already-configured local read/write
mediators, then compose:

- BrokerMediatorDispatcher with configured read_mediator and write_mediator
- UnixDomainBrokerServer with socket_path, peer_bindings, dispatcher, socket_mode
  0660 and socket_gid set to the worker group
- server.serve_forever()

The worker uses UnixDomainBrokerClient with socket_path and expected_server_uid set
to the broker UID. Its signing callback receives the fresh BrokerSessionContext; it
must place the session ID and channel-binding digest into the schema-valid signed
broker operation. Do not hard-code the signing private key in source or pass it to
the broker process.

The test suite now also launches the broker in a distinct child process and verifies
that the client receives a response from that process. That automated process test
uses the same OS UID for both sides; it does not prove cross-UID isolation.

Before deployment, run broker and worker under separate service identities, verify
socket ownership and permissions, demonstrate that the worker cannot open protected
storage or reach provider credentials directly, and run adversarial bypass and
concurrency suites under those actual service users.
