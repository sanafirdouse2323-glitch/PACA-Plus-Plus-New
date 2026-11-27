from __future__ import annotations

import json
from pathlib import Path


def test_industry_comparator_matrix_keeps_vendor_documentation_separate_from_live_tests():
    path = (
        Path(__file__).resolve().parents[1] / "docs" / "industry_comparator_matrix.json"
    )
    matrix = json.loads(path.read_text(encoding="utf-8"))

    assert matrix["schema_version"] == "1.0.0"
    assert matrix["repository"]["no_live_vendor_comparison_claim"] is True

    by_id = {item["id"]: item for item in matrix["comparators"]}
    assert len(by_id) == len(matrix["comparators"]) == 17
    assert (
        len([item for item in matrix["comparators"] if item["id"] != "paca-plus-plus"])
        == 16
    )

    vendor_ids = (
        "aws-bedrock-agentcore-temporal-policies",
        "nvidia-openshell",
        "microsoft-entra-agent-id",
        "google-cloud-agent-gateway",
    )
    research_ids = (
        "mcp-runtime-policy-enforcement-pep-2026",
        "progent",
        "camel",
        "multi-camel",
        "sapien",
        "forge-formal-policy-enforcement",
        "vigil",
        "agentspec",
        "caplease",
        "aid-guard",
        "delegateguard-purpose-bound-capabilities",
        "delegation-without-trust",
    )
    for comparator_id in vendor_ids:
        comparator = by_id[comparator_id]
        assert comparator["evidence_level"] == "D"
        assert comparator["live_test_status"] == "not_run"
        assert comparator["official_sources"]

    for comparator_id in research_ids:
        comparator = by_id[comparator_id]
        assert comparator["evidence_level"] == "D"
        assert comparator["live_test_status"] == "not_run"
        assert comparator["official_sources"]
        assert comparator["documented_capability_summary"]
        assert comparator["documented_scope_or_constraints"]
        assert comparator["not_established_by_documentation_alone"]
        assert comparator["live_test_requirements"]

    assert set(matrix["evidence_legend"]) == {"D", "I", "R", "V", "S", "F"}
    assert {item["id"] for item in matrix["baseline_profiles"]} == {
        "B0",
        "B1",
        "B2-native",
        "B3-layered",
        "P",
    }
    assert by_id["paca-plus-plus"]["evidence_level"] == ["I", "R", "S", "F"]
    for comparator in matrix["comparators"]:
        if comparator["id"] != "paca-plus-plus":
            assert comparator["live_test_status"] == "not_run"
            assert comparator["next_action"]

    # These controls address distinct research questions and must not be
    # collapsed into one synthetic "cohort" or ranked as interchangeable.
    assert by_id["caplease"]["relevant_research_dimensions"]
    assert by_id["aid-guard"]["relevant_research_dimensions"]
    assert (
        "authorization_to_effect_binding"
        in by_id["aid-guard"]["relevant_research_dimensions"]
    )
    assert "semantic_replay" in by_id["caplease"]["relevant_research_dimensions"]
