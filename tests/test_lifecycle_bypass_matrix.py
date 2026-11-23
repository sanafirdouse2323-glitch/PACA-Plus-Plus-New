from __future__ import annotations

import subprocess
import sys


def test_direct_subprocess_filesystem_effect_is_outside_python_mediation(tmp_path):
    target = tmp_path / "direct-effect.txt"
    program = (
        "from pathlib import Path; "
        "Path(" + repr(str(target)) + ").write_text('direct', encoding='utf-8')"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert target.read_text(encoding="utf-8") == "direct"


def test_direct_python_tool_function_is_outside_langchain_middleware(tmp_path):
    import pytest

    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    calls = []

    @tool
    def write_report(path: str, body: str) -> str:
        from pathlib import Path
        Path(path).write_text(body, encoding="utf-8")
        calls.append(path)
        return "written"

    target = tmp_path / "tool-direct.txt"
    # Invoking the tool itself is a direct host call. It does not enter an agent's
    # PACALangChainToolMiddleware hook and therefore must not be treated as mediated.
    assert write_report.invoke({"path": str(target), "body": "unmediated"}) == "written"
    assert calls == [str(target)]
    assert target.read_text(encoding="utf-8") == "unmediated"
