"""Public package interface for PACA++.

This module exposes the minimal, working core of the project: parsing,
compilation, evaluation, and provenance tracking.
"""

from .ast import EvaluationResult, Expression, Obligation, Policy, ProvenanceRecord
from .compiler import compile_policy, compile_policy_source
from .evaluator import evaluate_policy
from .parser import parse_policy
from .provenance import ProvenanceGraph

__version__ = "0.1.0"

__all__ = [
    "EvaluationResult",
    "Expression",
    "Obligation",
    "Policy",
    "ProvenanceGraph",
    "ProvenanceRecord",
    "compile_policy",
    "compile_policy_source",
    "evaluate_policy",
    "parse_policy",
]
