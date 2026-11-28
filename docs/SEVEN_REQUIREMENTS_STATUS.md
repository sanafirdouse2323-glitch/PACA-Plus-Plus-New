# Seven security requirements — implementation and evidence status

**Repository:** PACA-Plus-Plus-New
**Assessment snapshot:** 28 November 2026; repository `main` head `5cd0936710809108a661e81a5b1798049a6a26a3`. Repository settings were rechecked on 29 November 2026.
**Status:** Research implementation; not production-certified.
**Lifecycle behavior baseline:** PR #59 merge `c45732707cbfccf44bc4903300250f21184aa128`. The subsequent `5cd0936` commit extracted the message codec while preserving its historical import path; no intended behavior change is claimed.

This status record carries forward the earlier PR #49 assessment and includes the PR #59 lifecycle-session checks. PR #49 hardened release/replay controls; PR #59 added active-session checks to runtime delegation and message send/receive operations when lifecycle security is configured. Neither change establishes complete mediation or production certification. Historical evidence remains tied to its original commit and test configuration.

PR #59 validation on its implementation commit: CI run #1062 (`46165972063`) and release-validation run #841 (`46165972095`) passed. CI run #1070 (`46168770369`) and release-validation run #848 (`46168770423`) passed on the earlier `31faa24` snapshot. The current `5cd0936` snapshot moves the message codec into `paca/messages.py` while retaining its historical import path; no validation result for that refactor is recorded here. The live AgentDojo model benchmark was not run; adapter and dry-run checks are not live-agent results. No independent security review of PR #59 is recorded. Direct issuer/codec calls and paths outside the configured PACA runtime are not covered by its session check.

This record separates code that exists from system properties that have not yet been
demonstrated. A passing unit test is evidence only for the path it exercises.

## 1. Complete mediation through a separately trusted broker

**Partial implementation.** A Linux Unix-domain-socket broker transport is now
provided in paca/unix_broker.py. The kernel supplies peer credentials in both
directions: the broker maps the connecting worker UID/GID to fixed trusted identity
configuration, and the worker checks the expected broker UID. Each connection has
a fresh session and carries one signed operation. The transport can dispatch only
the existing local-file read/write mediators.

**Limited two-UID evidence now exists.** The root-only CI job runs the broker under
UID 0 and a worker under the unprivileged `nobody` UID. It verifies that the worker
can use the group-restricted broker socket to retrieve the content of a broker-read
mode-0600 test file, while that same file cannot be opened directly by the worker.
The child-process test also verifies that the broker can run in a separate process.

**Not established:** complete mediation of every path. This fixture covers one local
socket and one protected file, not all host resources. Workers can still bypass the
socket unless deployment policy removes direct filesystem, database, provider,
subprocess and framework access. The adapter is not automatically wired into every
PACAAgentRuntime or third-party tool. Production service users, real protected stores
and every relevant execution path still need host-specific denial testing.

## 2. Protect every consequential resource and provider commit

**Partial local protection; requirement not met globally.** Existing logical-resource,
local filesystem, SQLite and PostgreSQL shared-primary paths provide selected
commit fences, replay handling, version checks and revocation ordering.

**Not established:** remote provider mutation fencing, destination-side conditional
commit, atomic effect/revocation ordering across SaaS services, or protection for
unbrokered host/database/tool calls. Provider connectors remain read-only. Do not
claim that every consequential commit is protected.

## 3. Authenticated identity and production-grade key management

**Partial identity binding.** The new local transport binds a worker UID/GID to
preconfigured principal, workload, tenant, task and purpose fields using kernel
peer credentials. Ed25519 broker-operation signatures are already verified against
a configured trust key ring.

**Not production-grade key management.** This change does not implement an OIDC/
workload-identity provider, certificate authority, KMS/HSM key custody, secure key
generation, authenticated distribution, automated rotation, revocation propagation,
backup or recovery. The deployment must manage signing keys and trust configuration.
A static UID mapping is not a substitute for federated identity.

## 4. Semantic provenance across transformations and multi-agent communication

**Partial implementation.** Provenance labels and declared lineage edges propagate
through supported transformations. Model-generated transformations are conservatively
downgraded to untrusted integrity while retaining declared sensitivity, tenant and
origin restrictions. Synthetic fixtures cover paraphrase, summary, translation,
structured extraction, reconstruction, memory compaction/retrieval and agent transfer.
The configured `PACAAgentRuntime` also binds delegation and message send/receive
operations to the active lifecycle session, including principal, tenant, task, purpose
and policy epoch checks.

**Not established:** discovery of latent or omitted source dependencies in arbitrary
model outputs, proof that every integration supplies complete parent references, or
a general authenticated transformation-validation receipt that permits trust
promotion. Session binding on these runtime methods does not make all transports or
agent communication paths subject to lifecycle enforcement. The tests validate
declared lineage and selected runtime routes; they do not prove semantic dependency
inference or complete multi-hop continuity.

## 5. Direct bypasses, concurrency, replay and revocation races

**Partial test coverage.** Existing repository tests cover selected direct bypass
examples, local replay/permit reuse, concurrent authority/resource operations,
revocation ordering, response-loss retry and PostgreSQL shared-primary behavior.
The new transport tests cover peer UID/GID rejection, broker UID verification,
duplicate JSON keys, unsupported operations, per-connection session uniqueness,
concurrent connections and signed operation verification against the kernel-bound
session. The lifecycle communication tests also check delegation/session mismatch,
valid session-bound delegation, sender and recipient session checks, rejection before
message receipt consumption, kill-switch enforcement and audit-callback re-entry.

Some bypass tests intentionally demonstrate that direct host/framework calls remain
possible outside PACA hooks. They are evidence of current scope limits, not proof that
those bypasses are blocked. The new root-only CI fixture checks one unprivileged worker
against one protected file and one broker socket. Real application resources, other
host access paths, provider races, multi-host failures and sustained load remain
outstanding.

## 6. Matched live-agent experiments against strong existing baselines

**Partial baseline reproduction; matched live-agent study not complete.** The pinned
Ratchet workflow completed its independent core test suite and its published
paper-number reproduction script, retaining raw evidence as a workflow artifact.
The PR's six-point protocol and comparator register define evidence classes and
fair-comparison rules.

This does not yet constitute a matched PACA-versus-Ratchet experiment. The current
AgentDojo CI job exercises the adapter and CLI without model/API calls. Its live
model run requires a protected OPENAI_API_KEY and was skipped when that secret was
unavailable. Vendor tenant/host configurations and strongest compatible layered
baselines have not been executed. No residual violation surviving a strongest
correctly configured baseline has been demonstrated; no-gap findings must also be
reported honestly.

## 7. Independent adversarial security evaluation

**Not completed.** Internal code review, authored tests, formal models and benchmark
reproduction are not independent security assessment. No external assessor has
performed a scoped adversarial review or signed an evaluation report.

A valid independent evaluation requires a reviewer outside the implementation team,
a frozen build and threat model, access to a representative deployment, explicit
rules of engagement, reproducible findings, severity/risk ratings, remediation
retests and a report identifying tested and untested boundaries.

## Deployment and research gates

Before describing PACA++ as comprehensively effective or production-ready:

1. Deploy the broker and worker as separate identities; remove workers' direct access
   to protected stores and prove bypass attempts fail at the OS boundary.
2. Add a destination-side commit adapter for each supported provider and test
   conditional writes, replay, uncertain outcomes, retries and revocation races.
3. Integrate an authenticated workload identity source and managed key custody,
   rotation, revocation and recovery.
4. Define authenticated transformation evidence and validate provenance through live
   models, memory systems and inter-agent transfer; retain fail-closed behavior when
   dependencies are unknown.
5. Run a pre-registered matched experiment using identical models, tasks, budgets,
   permissions and host assumptions, including a strong layered baseline and live
   agent executions. Publish raw traces, exclusions, cost, latency, utility, attack
   success and uncertainty.
6. Commission an independent adversarial evaluation after a frozen candidate build.

Until these gates are met, report the project as a research prototype with meaningful
selected-path controls—not as universal agent security, complete mediation or a
production security product.
