# Changelog

## 0.3.2 — 2026-11-09

This is a packaging and release-process update. It does not claim a new security
guarantee or a measured improvement in real-agent attack resistance.

- Synchronises the project version in `pyproject.toml` and `paca.__version__`.
- Adds a tag-driven GitHub Release workflow that verifies the tag against package
  metadata, runs the test suite and static checks, builds both a wheel and source
  distribution, and checks installation of the built artifacts in clean environments.
- Attaches the Python distribution files and their SHA-256 checksums to the GitHub
  Release, and publishes versioned GitHub Container Registry images from the existing
  Python 3.13 multi-stage Dockerfile.
- Adds a regression test to keep the runtime and installed distribution versions aligned.

The PACA++ reference API remains a local demonstration/reference interface. It does
not execute external effects and is not a production authorization executor. The
repository's deterministic and AgentDojo adapter tests must not be interpreted as
independent real-agent security-effectiveness measurements.
