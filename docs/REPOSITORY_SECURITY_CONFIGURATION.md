# Repository security configuration — administration required

**Scope:** PACA-Plus-Plus-New only.

## Observed repository setting

On 29 November 2026, the GitHub API recheck reported that the default `main` branch was not protected (`protected: false`) and the repository rulesets endpoint returned an empty list. The available GitHub connection for this work can inspect these settings but does not expose repository-administration write permission or an action to create/enforce rulesets. Therefore, this document is an administrator action plan; it is not evidence that branch protection has been enabled.

## Required `main` ruleset

A repository administrator should open **Settings → Rules → Rulesets → New branch ruleset** and create an active ruleset targeting the exact branch `main`.

Enable these protections:

1. Require a pull request before merging. Require at least one approval from a reviewer other than the PR author; dismiss stale approvals when new commits are pushed. Because the repository owner is also the primary contributor, add at least one separate trusted reviewer; the author must not approve their own pull request.
2. Require all review conversations to be resolved.
3. Require the branch to be up to date before merging, if the team can support that workflow.
4. Require the stable CI checks for the default branch: the Python test matrix for 3.10, 3.11, 3.12 and 3.13; wheel smoke test; AgentDojo adapter integration; lint/type checks; PostgreSQL checkpoint integration; LangGraph integration; all three `Core security contract` profile checks; broker UID isolation; and the Docker build-only check.
5. Require the release validation/build check for changes covered by `.github/workflows/release.yml`.
6. Block force pushes and branch deletion. Apply the ruleset to administrators and avoid bypass actors. Any emergency bypass should be time-limited, documented and reviewed after use.

Do **not** make the real-model AgentDojo benchmark a required check. It now runs only when a maintainer explicitly adds the `run-live-agentdojo` label to a pull request and the `OPENAI_API_KEY` secret is configured. Without that label or credential, the job is skipped. The adapter tests and dry-run preflight remain part of normal CI; they do not make model calls. A skipped credential-dependent experiment must not block otherwise-valid code changes.

GitHub displays the exact required-check names after the workflows have run on pull requests. Select the stable job/check names from the actual runs rather than guessing names from YAML display titles.

## Release and workflow controls

The workflows now separate image validation from image publication:

- The CI `docker-build` job has `contents: read` only. It builds and loads a local image after the test/security jobs pass, but it has no `packages: write` permission, does not log in to GHCR and sets `push: false`. A pull request or ordinary push to `main` therefore cannot publish a container image through this job.
- The release workflow validates the package version and full test/security suite. Container publication is available only for a pushed `v*` tag whose name matches the project version, whose commit is the tag target, whose commit is reachable from `origin/main`, and for which a GitHub Release does not already exist.
- The tag verification job has an explicit publisher allowlist containing `sanafirdouse2323-glitch`. Change that allowlist only through a reviewed workflow change. This is a repository-side fail-closed control, not a substitute for limiting who can create tags in GitHub settings.
- The tag verification job also requires the repository Actions variable `PACA_RELEASE_GOVERNANCE_VERIFIED` to equal the exact string `true`. The variable is intentionally absent by default. Set it only after the `main` ruleset, `v*` tag ruleset and `paca-release` environment protection have been applied and independently rechecked. If any of those settings are removed or weakened, remove/reset the variable immediately. The workflow cannot independently query protected branch/ruleset settings because its normal `GITHUB_TOKEN` does not have repository-administration read access.
- GitHub Release publication uses the `paca-release` environment. An administrator must configure that environment with at least one required reviewer, disable self-review, and restrict deployment branches/tags to version tags matching `v*`. Container publication waits for the approved GitHub Release job to finish.
- The release publishes version-specific image tags and updates `latest` only after the tag checks and release approval. The CI workflow never updates `latest`.
- Keep GitHub Actions permissions least-privileged. Only the release container job has `packages: write`; do not grant that permission to CI or pull-request jobs.
- Treat the `run-live-agentdojo` label as an explicit spend approval. Add it only after confirming the model, task subset, iteration limit and intended API spend; remove it when the run is no longer needed.
- Protect version tags matching `v*` with a separate active tag ruleset. Restrict tag creation to the intended release publisher, and block tag update/deletion. The workflow allowlist is a second control, not a replacement for the tag ruleset.
- Preserve the release workflow's version/tag validation and clean package-install checks. Do not bypass failing release validation to publish artifacts.

A GitHub Actions workflow cannot activate a branch ruleset on its own. The GitHub connection used for this repository can read files and Actions results but does not have repository-administration write permission. A repository administrator must apply the `main` ruleset, the `v*` tag ruleset and the `paca-release` environment protection directly in GitHub settings. Only after verifying those settings should the administrator create the repository Actions variable `PACA_RELEASE_GOVERNANCE_VERIFIED=true`. Until then, release publication is intentionally blocked by the workflow. Do not claim that branch protection, tag protection or environment approval is active merely because the variable exists; periodically recheck the actual settings and reset the variable if governance is changed.

## Validation after the administrator applies the ruleset

1. Fetch the repository branch/ruleset settings and confirm `main` is protected by an active ruleset.
2. Open a test pull request and confirm the required checks appear and block merging while pending or failing.
3. Confirm a direct push and force push to `main` are rejected for ordinary contributors.
4. Confirm CI builds the Docker image locally without GHCR login or package-write permission, and that pushes to `main` do not update any registry tag.
5. Confirm a valid, owner-authorised version tag is rejected unless it targets a commit reachable from `main`; confirm the `paca-release` reviewer gate blocks publication until approved.
6. Confirm unauthorized actors cannot create, move or delete `v*` tags and cannot bypass the `main` branch ruleset.

Until an administrator completes these steps and verifies the result in GitHub, the repository must be described as **having a proposed branch-protection configuration, not enforced branch protection**.
