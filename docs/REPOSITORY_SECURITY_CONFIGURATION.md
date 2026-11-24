# Repository security configuration — administration required

**Scope:** PACA-Plus-Plus-New only.

## Observed repository setting

On 24 November 2026, the GitHub API reported that the default `main` branch was not protected and that the repository had no rulesets. The available GitHub connection for this work can inspect these settings but does not have the repository-administration write permission required to create or enforce a ruleset. Therefore, this document is an administrator action plan; it is not evidence that branch protection has been enabled.

## Required `main` ruleset

A repository administrator should open **Settings → Rules → Rulesets → New branch ruleset** and create an active ruleset targeting the exact branch `main`.

Enable these protections:

1. Require a pull request before merging. Require at least one approval from a reviewer other than the PR author; dismiss stale approvals when new commits are pushed.
2. Require all review conversations to be resolved.
3. Require the branch to be up to date before merging, if the team can support that workflow.
4. Require the stable CI checks for the default branch: the Python test matrix for 3.10, 3.11, 3.12 and 3.13; wheel smoke test; AgentDojo adapter integration; lint/type checks; PostgreSQL checkpoint integration; LangGraph integration; and Docker build.
5. Require the release validation/build check for changes covered by `.github/workflows/release.yml`.
6. Block force pushes and branch deletion. Apply the ruleset to administrators and avoid bypass actors. Any emergency bypass should be time-limited, documented and reviewed after use.

Do **not** make the real-model AgentDojo benchmark a required check: the workflow intentionally skips that job when `OPENAI_API_KEY` is unavailable. A skipped credential-dependent experiment must not block otherwise-valid code changes.

GitHub displays the exact required-check names after the workflows have run on pull requests. Select the stable job/check names from the actual runs rather than guessing names from YAML display titles.

## Release and workflow controls

- Keep GitHub Actions permissions least-privileged. The CI Docker job should publish only after a protected push to `main`; it must not publish images from untrusted pull-request code.
- Protect version tags matching `v*` with a separate tag ruleset. Restrict who may create or move release tags.
- Keep package/image publication credentials unavailable to arbitrary pull-request code. Review workflow permission changes as security-sensitive code.
- Preserve the release workflow's version/tag validation and clean package-install checks. Do not bypass failing release validation to publish artifacts.

## Validation after the administrator applies the ruleset

1. Fetch the repository branch/ruleset settings and confirm `main` is protected by an active ruleset.
2. Open a test pull request and confirm the required checks appear and block merging while pending or failing.
3. Confirm a direct push and force push to `main` are rejected for ordinary contributors.
4. Confirm PR CI does not publish a GHCR image and a protected `main` push is the only branch-based image publication path.
5. Confirm a release tag cannot be created or moved by an unauthorized actor.

Until an administrator completes these steps and verifies the result in GitHub, the repository must be described as **having a proposed branch-protection configuration, not enforced branch protection**.
