# Changelog

## Unreleased — 2026-11-28

This section records changes merged to `main` after the 0.3.2 packaging release. It does not claim production readiness or improved real-agent attack resistance.

- Separates shared provider OAuth/HTTP/capture primitives from the Gmail, Microsoft Graph, Slack and Qdrant read-only adapters while retaining the `paca.integrations.providers` facade, public exports, private HTTP wrapper and pickle names.
- Adds durable provenance and memory reference components, signed capability envelopes, policy epochs, revocation, per-capability and tenant/task aggregate quotas, and persistent message replay receipts.
- Adds an optional PostgreSQL shared-primary authority registry and an Ed25519 issuer/verifier separation primitive.
- Adds read-only Gmail, Microsoft Graph, Slack and Qdrant provider adapters with bounded response handling and provenance capture; CI uses mocked provider HTTP.
- Adds AgentDojo, LangGraph, LangChain and PostgreSQL checkpoint integrations, plus opt-in Docker worker and local resource-commit reference components.
- Hardens the consequential monitor profile and Qdrant tenant filtering; reconciles project documentation and security boundaries.
- Expands repository checks and documents remaining bypass, identity, key-management, remote-commit and evaluation gaps.
- Hardens strict resource commits with concrete built-in executor allow-listing, runtime-bound authority/registry checks, built-in sync/async dispatch and sealed filesystem adapter configuration.
- Serializes in-process broker provenance checks against lineage revocation on one host using the shared SQLite provenance repository; distributed and multi-host revocation consistency remain unsupported.
- Separates logical resource values from filesystem recovery sidecar state and preserves immutable committed-version evidence for filesystem journal recovery; legacy rows are retained without guessing their original backend.
- Gates Docker image publication on the complete non-credential-dependent CI set and expands mypy checks to selected security-critical modules and untyped function bodies.
- Adds PR #48 lifecycle-security reference control: explicit session/principal/tenant/task/purpose binding, policy-epoch checks, fail-closed provenance/tool checks, one-use commit authorization and a one-way stop switch for PACA-managed runtime calls. This does not establish complete mediation or provider/host enforcement.
- Bounds the lifecycle controller's process-local committed-effect receipt cache and fails closed at capacity; this cache is not durable or shared across processes.
- Extracts the inter-agent `HMACAgentMessageCodec` into `paca/messages.py` without changing its 16,002-character implementation, while preserving `paca.memory` and package-level imports, the historical class name and pickle compatibility. Adds dedicated behaviour/compatibility and installed-package smoke tests.
- Adds lifecycle-session checks to `PACAAgentRuntime.delegate()`, `send_message()` and `receive_message()` when lifecycle security is configured (PR #59). The checks bind the relevant capability to the active principal, tenant, task, purpose and policy epoch; regression tests and an offline SQLite example cover selected trusted and untrusted paths. This does not mediate direct issuer/codec calls or other transports and does not establish complete lifecycle mediation.
- Reconciles README, lifecycle status and research documentation with the merged PR #59 implementation; this was a documentation-only change (PR #60).
- Gates Docker publication on the Python matrix, wheel smoke test, AgentDojo adapter, lint/type checks, LangGraph, PostgreSQL checkpoint, installation-profile security contracts and broker UID-isolation checks.
- Strengthens release validation with repository-wide Ruff checks, selected security-critical mypy checks, profile and broker-isolation tests, and a tag-ancestry check requiring release commits to be reachable from `main`.
- Changes the CI Docker job to build and locally inspect an image without GHCR login or package-write permission; ordinary `main` pushes no longer publish container tags.
- Makes the live AgentDojo model benchmark opt-in through the `run-live-agentdojo` pull-request label, preventing routine PR validation from unexpectedly initiating billable model calls.
- Restricts container publication to validated version-tag releases, checks the release-triggering account against the repository-owner publisher allowlist, requires the administrator-set `PACA_RELEASE_GOVERNANCE_VERIFIED=true` attestation, and places GitHub Release publication behind the `paca-release` environment. The administrator must configure required reviewers, branch protection and tag protection in GitHub settings before enabling the attestation.

These are reference implementations. They do not establish complete lifecycle mediation or independently measured real-world security effectiveness.

## 0.3.2 — 2026-11-09

This was a packaging and release-process update. It did not claim a new security guarantee or a measured improvement in real-agent attack resistance.

- Synchronised the project version in `pyproject.toml` and `paca.__version__`.
- Added a tag-driven GitHub Release workflow with version/tag validation, tests, static checks, wheel and source-distribution builds, and clean-install smoke tests.
- Added SHA-256 checksums and versioned GitHub Container Registry images.
- Added a regression test to keep the runtime and installed distribution versions aligned.

The PACA++ reference API remains a local demonstration interface. It does not execute external effects and is not a production authorization executor.