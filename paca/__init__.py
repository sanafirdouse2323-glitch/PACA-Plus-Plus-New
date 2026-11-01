"""PACA++ - Provenance-Anchored Continuous Authorization for autonomous LLM agents."""
from .ast import EvaluationResult, Expression, Obligation, Policy, PolicySet, ProvenanceRecord
from .compiler import compile_policy, compile_policy_source
from .engine import PolicyEngine
from .evaluator import evaluate_policy, evaluate_policy_set
from .parser import parse_policy, parse_policy_file, parse_policy_set
from .provenance import Arg, Label, ProvenanceGraph, derive

__version__ = "0.3.0"
__all__ = [n for n in dir() if not n.startswith("_")]
