from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_offline_lifecycle_demo_emits_benign_and_poisoned_sink_results(tmp_path):
    repository_root = Path(__file__).resolve().parents[1]
    script = repository_root / "examples" / "lifecycle_security_demo.py"
    report_path = tmp_path / "lifecycle-demo.json"

    completed = subprocess.run(
        [sys.executable, str(script), "--output", str(report_path)],
        cwd=repository_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
    )

    assert completed.returncode == 0, (
        f"demo failed with exit code {completed.returncode}\\n"
        f"stdout: {completed.stdout}\\nstderr: {completed.stderr}"
    )
    assert completed.stdout == ""
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["mode"] == "deterministic local reference path; no live LLM or provider"

    benign, poisoned = report["scenarios"]
    assert benign["scenario"] == "benign"
    assert benign["outcome"]["decision"] == "allow"
    assert benign["outcome"]["sink_row"]["version"] == 1
    assert benign["outcome"]["sink_row"]["commit_nonce_present"] is True

    assert poisoned["scenario"] == "poisoned"
    assert poisoned["outcome"]["decision"] == "deny"
    assert poisoned["outcome"]["sink_row"] is None
