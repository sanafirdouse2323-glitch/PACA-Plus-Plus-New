from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ci_docker_job_is_build_only_and_has_no_registry_write_access():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    docker_start = workflow.index("  docker-build:\n")
    docker_end = workflow.index("\n  langgraph-postgres-checkpoint:", docker_start)
    docker_job = workflow[docker_start:docker_end]
    needs_start = docker_job.index("    needs:\n")
    steps_start = docker_job.index("    steps:\n", needs_start)
    needs = docker_job[needs_start:steps_start]

    required = (
        "tests",
        "wheel-smoke-test",
        "agentdojo-integration",
        "lint",
        "langgraph-postgres-checkpoint",
        "langgraph-integration",
        "security-profile-contracts",
        "broker-uid-isolation",
    )
    for job_name in required:
        assert f"      - {job_name}\n" in needs

    # The CI job must be incapable of publishing even on a push to main.
    assert "packages: write" not in docker_job
    assert "docker/login-action" not in docker_job
    assert "ghcr.io/" not in docker_job
    assert "push: false" in docker_job
    assert "load: true" in docker_job
    assert "docker image inspect" in docker_job


def test_release_validation_runs_repository_and_security_contract_checks():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    validation = workflow.split("\n  verify-release-tag:", maxsplit=1)[0]
    assert "python -m ruff check ." in validation
    assert "python -m ruff format --check ." in validation
    assert "--check-untyped-defs" in validation
    assert "for profile in core extended research" in validation
    assert "tests/test_profile_security_contract.py" in validation
    assert (
        "tests/test_unix_broker.py -k "
        "unprivileged_worker_uses_broker_without_direct_file_access"
    ) in validation


def test_release_tag_must_be_reachable_from_main_history():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "git fetch origin main:refs/remotes/origin/main --force" in workflow
    assert (
        'git merge-base --is-ancestor "$tagged_sha" refs/remotes/origin/main'
    ) in workflow


def test_registry_publication_is_limited_to_validated_version_tag_releases():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    # No main-push publication path is permitted in the CI workflow.
    ci_docker = ci_workflow.split("  docker-build:\n", 1)[1].split(
        "\n  langgraph-postgres-checkpoint:", 1
    )[0]
    assert "packages: write" not in ci_docker
    assert "docker/login-action" not in ci_docker
    assert "push: false" in ci_docker
    assert "ghcr.io/" not in ci_docker

    # Publishing requires a version tag, successful verification, an owner-only
    # actor allowlist, and main-line ancestry.
    verify = workflow.split("\n  verify-release-tag:", 1)[1].split(
        "\n  publish-github-release:", 1
    )[0]
    assert "github.ref_type == 'tag'" in workflow
    assert "EXPECTED_RELEASE_ACTOR: sanafirdouse2323-glitch" in verify
    assert 'if [ "$EVENT_ACTOR" != "$EXPECTED_RELEASE_ACTOR" ]' in verify
    assert "EXPECTED_TAG" in verify
    assert 'git merge-base --is-ancestor "$tagged_sha" refs/remotes/origin/main' in verify

    publisher = workflow.split("\n  publish-container:", 1)[1]
    assert "packages: write" in publisher
    assert "push: true" in publisher
    assert "paca-plus-plus-new:latest" in publisher
    assert "needs: [validate-and-build, verify-release-tag, publish-github-release]" in publisher


def test_release_publication_uses_a_protected_environment():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    publisher = workflow.split("\n  publish-github-release:", 1)[1].split(
        "\n  publish-container:", 1
    )[0]
    assert "environment:" in publisher
    assert "name: paca-release" in publisher
