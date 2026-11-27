from __future__ import annotations

import pytest

from paca.evaluation_statistics import (
    CONFIRMATORY_TEMPLATE_FLOOR,
    paired_template_effect,
)


def _templates(count: int):
    return [
        {
            "template_id": f"attack-family-{index:02d}",
            "eligible_opportunities": 10,
            "control_prohibited_effects": 4,
            "treatment_prohibited_effects": 2,
        }
        for index in range(count)
    ]


def test_paired_template_effect_uses_equal_weight_independent_template_rates():
    result = paired_template_effect(
        [
            {
                "template_id": "workflow-a",
                "eligible_opportunities": 10,
                "control_prohibited_effects": 4,
                "treatment_prohibited_effects": 2,
            },
            {
                "template_id": "workflow-b",
                "eligible_opportunities": 2,
                "control_prohibited_effects": 1,
                "treatment_prohibited_effects": 0,
            },
        ],
        bootstrap_replicates=500,
        seed=7,
    )

    # Template A contributes -0.20 and template B contributes -0.50.
    # The estimand weights templates equally, not each raw opportunity equally.
    assert result["treatment_minus_control_estimate"] == pytest.approx(-0.35)
    assert result["independent_template_count"] == 2
    assert result["status"] == "exploratory_only"
    assert result["confirmatory_eligible"] is False
    assert result["percentile_interval_95"][0] <= -0.35
    assert result["percentile_interval_95"][1] >= -0.35


def test_paired_template_effect_marks_30_independent_templates_as_review_eligible():
    result = paired_template_effect(_templates(CONFIRMATORY_TEMPLATE_FLOOR), seed=11)

    assert result["independent_template_count"] == 30
    assert result["confirmatory_eligible"] is True
    assert result["status"] == "eligible_for_separate_power_and_protocol_review"
    assert result["treatment_minus_control_estimate"] == pytest.approx(-0.2)


def test_paired_template_effect_is_deterministic_for_a_frozen_seed():
    templates = _templates(5)
    first = paired_template_effect(templates, bootstrap_replicates=300, seed=19)
    second = paired_template_effect(templates, bootstrap_replicates=300, seed=19)

    assert first == second


@pytest.mark.parametrize(
    "bad_templates",
    [
        [],
        [
            {
                "template_id": "same",
                "eligible_opportunities": 10,
                "control_prohibited_effects": 1,
                "treatment_prohibited_effects": 0,
            },
            {
                "template_id": "same",
                "eligible_opportunities": 10,
                "control_prohibited_effects": 1,
                "treatment_prohibited_effects": 0,
            },
        ],
        [
            {
                "template_id": "missing-denominator",
                "eligible_opportunities": 0,
                "control_prohibited_effects": 0,
                "treatment_prohibited_effects": 0,
            }
        ],
        [
            {
                "template_id": "out-of-range",
                "eligible_opportunities": 2,
                "control_prohibited_effects": 3,
                "treatment_prohibited_effects": 0,
            }
        ],
        [
            {
                "template_id": "boolean-count",
                "eligible_opportunities": True,
                "control_prohibited_effects": 0,
                "treatment_prohibited_effects": 0,
            }
        ],
    ],
)
def test_paired_template_effect_rejects_invalid_or_pseudoreplicated_inputs(
    bad_templates,
):
    with pytest.raises((TypeError, ValueError)):
        paired_template_effect(bad_templates, bootstrap_replicates=50)


def test_paired_template_effect_rejects_zero_bootstrap_replicates():
    with pytest.raises(ValueError, match="bootstrap_replicates"):
        paired_template_effect(_templates(2), bootstrap_replicates=0)
