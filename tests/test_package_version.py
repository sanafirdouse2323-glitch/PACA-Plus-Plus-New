"""Keep the import-time version aligned with the built distribution metadata."""

from importlib.metadata import version

import paca


def test_runtime_version_matches_distribution_metadata() -> None:
    assert paca.__version__ == version("paca-plus-plus")
