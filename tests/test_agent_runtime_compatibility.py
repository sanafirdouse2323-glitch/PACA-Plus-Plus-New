from __future__ import annotations

import paca
from paca.agent_runtime import PACAAgentRuntime as ExtractedRuntime
from paca.memory import PACAAgentRuntime as LegacyRuntime


def test_agent_runtime_legacy_and_package_imports_are_compatible():
    assert LegacyRuntime is ExtractedRuntime
    assert paca.PACAAgentRuntime is ExtractedRuntime
    assert paca.memory.PACAAgentRuntime is ExtractedRuntime
    assert ExtractedRuntime.__module__ == "paca.memory"
