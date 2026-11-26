"""Template-level statistical summaries for paired agent-security evaluations.

The independent analysis unit is a distinct workflow/attack template. Replays,
model seeds and parameter variants from one underlying construction must be
aggregated into that template before calling this module.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from typing import TypedDict


CONFIRMATORY_TEMPLATE_FLOOR = 30


class TemplateOutcome(TypedDict):
    """Aggregated paired outcomes for one independent scenario template."""

    template_id: str
    eligible_opportunities: int
    control_prohibited_effects: int
    treatment_prohibited_effects: int


def _require_count(name: str, value: object, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer greater than or equal to {minimum}")
    return value


def _percentile(sorted_values: list[float], probability: float) -> float:
    """Return a linearly interpolated sample percentile (type-7 convention)."""
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be between zero and one")
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] + (
        sorted_values[upper] - sorted_values[lower]
    ) * fraction


def paired_template_effect(
    templates: Sequence[TemplateOutcome],
    *,
    bootstrap_replicates: int = 10_000,
    seed: int = 20261126,
) -> dict[str, object]:
    """Estimate treatment-minus-control prohibited-effect rates by whole template.

    Each template contributes one paired rate difference, regardless of how many
    replays or eligible opportunities it contains. The same predeclared eligible
    opportunity count is used for both arms. An opportunity blocked by either
    arm must remain in this shared denominator; do not remove it after observing
    the decision.

    The returned percentile interval is descriptive uncertainty, not a test of
    superiority, a power analysis, or proof that the templates are representative.
    A result with fewer than 30 independent templates is marked exploratory-only.
    A result with 30 or more templates is merely eligible for a separately
    preregistered confirmatory design and power/coverage assessment.
    """
    if not isinstance(templates, Sequence) or isinstance(templates, (str, bytes)):
        raise TypeError("templates must be a non-empty sequence of template outcomes")
    if not templates:
        raise ValueError("at least one independent template is required")
    bootstrap_replicates = _require_count(
        "bootstrap_replicates", bootstrap_replicates, minimum=1
    )
    if bootstrap_replicates > 1_000_000:
        raise ValueError("bootstrap_replicates must not exceed 1,000,000")
    seed = _require_count("seed", seed, minimum=0)

    seen: set[str] = set()
    template_differences: list[float] = []
    details: list[dict[str, object]] = []

    for index, row in enumerate(templates):
        if not isinstance(row, dict):
            raise TypeError(f"templates[{index}] must be a mapping")
        template_id = row.get("template_id")
        if (
            not isinstance(template_id, str)
            or not template_id.strip()
            or len(template_id) > 256
        ):
            raise ValueError(
                f"templates[{index}].template_id must be a non-empty string of at most 256 characters"
            )
        if template_id in seen:
            raise ValueError(f"duplicate independent template_id: {template_id!r}")
        seen.add(template_id)

        opportunities = _require_count(
            f"templates[{index}].eligible_opportunities",
            row.get("eligible_opportunities"),
            minimum=1,
        )
        control = _require_count(
            f"templates[{index}].control_prohibited_effects",
            row.get("control_prohibited_effects"),
            minimum=0,
        )
        treatment = _require_count(
            f"templates[{index}].treatment_prohibited_effects",
            row.get("treatment_prohibited_effects"),
            minimum=0,
        )
        if control > opportunities or treatment > opportunities:
            raise ValueError(
                f"prohibited-effect counts cannot exceed eligible opportunities for {template_id!r}"
            )

        control_rate = control / opportunities
        treatment_rate = treatment / opportunities
        difference = treatment_rate - control_rate
        template_differences.append(difference)
        details.append(
            {
                "template_id": template_id,
                "eligible_opportunities": opportunities,
                "control_rate": control_rate,
                "treatment_rate": treatment_rate,
                "treatment_minus_control": difference,
            }
        )

    template_count = len(template_differences)
    estimate = math.fsum(template_differences) / template_count
    rng = random.Random(seed)
    bootstrap_estimates: list[float] = []
    for _ in range(bootstrap_replicates):
        sample = rng.choices(template_differences, k=template_count)
        bootstrap_estimates.append(math.fsum(sample) / template_count)
    bootstrap_estimates.sort()

    lower = _percentile(bootstrap_estimates, 0.025)
    upper = _percentile(bootstrap_estimates, 0.975)
    confirmatory_eligible = template_count >= CONFIRMATORY_TEMPLATE_FLOOR

    return {
        "estimand": (
            "unweighted mean of independent template-level "
            "(treatment prohibited-effect rate - control prohibited-effect rate)"
        ),
        "direction": "negative values indicate fewer prohibited effects under treatment",
        "independent_template_count": template_count,
        "confirmatory_template_floor": CONFIRMATORY_TEMPLATE_FLOOR,
        "status": (
            "eligible_for_separate_power_and_protocol_review"
            if confirmatory_eligible
            else "exploratory_only"
        ),
        "confirmatory_eligible": confirmatory_eligible,
        "treatment_minus_control_estimate": estimate,
        "percentile_interval_95": [lower, upper],
        "bootstrap_replicates": bootstrap_replicates,
        "bootstrap_seed": seed,
        "template_results": details,
        "limitations": [
            "Template independence is an investigator-declared design property, not inferred by this function.",
            "Repeated runs and parameter variants must be aggregated under their original template_id.",
            "The percentile interval does not establish power, coverage, causality, deployment representativeness or safety.",
            "Uncertain sink outcomes require a separately declared sensitivity analysis.",
            "Security, legitimate utility and operating cost must be analysed as separate outcomes.",
        ],
    }


__all__ = [
    "CONFIRMATORY_TEMPLATE_FLOOR",
    "TemplateOutcome",
    "paired_template_effect",
]
