from __future__ import annotations

import json
from pathlib import Path


def test_industry_comparator_matrix_keeps_vendor_documentation_separate_from_live_tests():
    path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "industry_comparator_matrix.json"
    )
    matrix = json.loads(path.read_text(encoding="utf-8"))

    assert matrix["schema_version"] == "1.0.0"
    assert matrix["repository"]["no_live_vendor_comparison_claim"] is True

    by_id = {item["id"]: item for item in matrix["comparators"]}
    assert len(by_id) == len(matrix["comparators"])
    for vendor_id in (
        "aws-bedrock-agentcore-temporal-policies",
        "nvidia-openshell",
        "microsoft-entra-agent-id",
        "google-cloud-agent-gateway",
    ):
        comparator = by_id[vendor_id]
        assert comparator["evidence_level"] == "D"
        assert comparator["live_test_status"] == "not_run"
        assert comparator["official_sources"]

    assert set(matrix["evidence_legend"]) == {"D", "I", "R", "V", "S", "F"}
    assert {item["id"] for item in matrix["baseline_profiles"]} == {
        "B0",
        "B1",
        "B2-native",
        "B3-layered",
        "P",
    }
    assert by_id["paca-plus-plus"]["evidence_level"] == ["I", "R", "S", "F"]
