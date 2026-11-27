from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _job_block(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    assert match is not None, f"workflow job {job_name!r} is missing"
    return match.group(1)


def test_docker_publication_waits_for_all_non_credential_security_jobs():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    job = _job_block(workflow, "docker-build")
    needs = re.search(r"(?ms)^    needs:\n(.*?)(?=^    [A-Za-z0-9_-]+:|^    steps:)", job)
    assert needs is not None, "docker-build must declare explicit dependencies"
    required = {
        "tests",
        "wheel-smoke-test",
        "agentdojo-integration",
        "lint",
        "langgraph-postgres-checkpoint",
        "langgraph-integration",
        "security-profile-contracts",
        "broker-uid-isolation",
    }
    declared = set(re.findall(r"^      - ([A-Za-z0-9_-]+)$", needs.group(1), re.MULTILINE))
    assert required <= declared


def test_release_validation_runs_repository_and_security_contract_checks():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    validation = _job_block(workflow, "validate-and-build")
    assert "python -m ruff check ." in validation
    assert "python -m ruff format --check ." in validation
    assert "--check-untyped-defs" in validation
    assert "for profile in core extended research" in validation
    assert "tests/test_profile_security_contract.py" in validation
    assert "tests/test_unix_broker.py -k unprivileged_worker_uses_broker_without_direct_file_access" in validation


def test_release_tag_must_be_reachable_from_main_history():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "git fetch origin main:refs/remotes/origin/main --force" in workflow
    assert 'git merge-base --is-ancestor "$tagged_sha" refs/remotes/origin/main' in workflow
