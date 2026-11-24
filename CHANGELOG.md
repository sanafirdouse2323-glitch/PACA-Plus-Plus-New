# Changelog

## Unreleased — 2026-11-24

This section records changes merged to `main` after the 0.3.2 packaging release. It does not claim production readiness or improved real-agent attack resistance.

- Adds durable provenance and memory reference components, signed capability envelopes, policy epochs, revocation, per-capability and tenant/task aggregate quotas, and persistent message replay receipts.
- Adds an optional PostgreSQL shared-primary authority registry and an Ed25519 issuer/verifier separation primitive.
- Adds read-only Gmail, Microsoft Graph, Slack and Qdrant provider adapters with bounded response handling and provenance capture; CI uses mocked provider HTTP.
- Adds AgentDojo, LangGraph, LangChain and PostgreSQL checkpoint integrations, plus opt-in Docker worker and local resource-commit reference components.
- Hardens the consequential monitor profile and Qdrant tenant filtering; reconciles project documentation and security boundaries.
- Expands repository checks and documents remaining bypass, identity, key-management, remote-commit and evaluation gaps.

These are reference implementations. They do not establish complete lifecycle mediation or independently measured real-world security effectiveness.

## 0.3.2 — 2026-11-09

This was a packaging and release-process update. It did not claim a new security guarantee or a measured improvement in real-agent attack resistance.

- Synchronised the project version in `pyproject.toml` and `paca.__version__`.
- Added a tag-driven GitHub Release workflow with version/tag validation, tests, static checks, wheel and source-distribution builds, and clean-install smoke tests.
- Added SHA-256 checksums and versioned GitHub Container Registry images.
- Added a regression test to keep the runtime and installed distribution versions aligned.

The PACA++ reference API remains a local demonstration interface. It does not execute external effects and is not a production authorization executor.