from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docker_publication_waits_for_all_non_credential_security_jobs():
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
