# PACA++

Provenance-Anchored Continuous Authorization Framework for Autonomous LLM Agents.

## Overview

PACA++ is a small policy framework for expressing authorization decisions and tracking the provenance of the facts used to reach those decisions. The implementation here intentionally provides a minimal, dependency-light core that is testable and extensible, rather than claiming a full production-grade authorization engine.

The current codebase focuses on three core ideas:

- Parse a compact policy DSL into a structured AST.
- Compile the policy into a normalized, engine-agnostic representation.
- Evaluate the policy against a runtime context while recording provenance.

## Architecture

The project is organized around a simple pipeline:

1. Policy text is parsed in `paca/parser.py`.
2. A normalized policy representation is produced by `paca/compiler.py`.
3. Policy evaluation happens in `paca/evaluator.py`.
4. Provenance is tracked in `paca/provenance.py`.
5. Backend shims, such as `compiler_asp.py` and `evaluator_cedar.py`, adapt the same core logic to backend-specific naming.

This design allows the framework to support future backends without changing the core policy semantics.

## Policy language

The reference DSL is intentionally simple:

```text
permit readFile when user.role == admin and user.department == engineering

deny deleteFile when user.role != admin
```

You can also optionally attach an obligation:

```text
permit readFile when user.role == admin with obligation audit_log(user.id)
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Basic usage

```python
from paca.parser import parse_policy
from paca.evaluator import evaluate_policy

policy = parse_policy(
    "permit readFile when user.role == admin and user.department == engineering"
)
context = {
    "user": {"role": "admin", "department": "engineering"},
}
result = evaluate_policy(policy, context)
print(result.decision)
```

## Current maturity

This repository is an early research scaffold. It is intentionally conservative and does not claim to provide full solver-backed authorization, semantic verification, or a complete policy language implementation. The goal of the current codebase is to make the project executable, testable, and structurally realistic without inventing unsupported features.

## Project structure

```text
paca/
  ast.py          # dataclasses for expressions, policies, results
  parser.py       # reference policy parser
  compiler.py     # compiler to normalized policy format
  evaluator.py    # core evaluator
  provenance.py   # provenance tracking
  obligations.py  # obligation helpers
  fuzzer.py       # lightweight policy/context generator
examples/
  sample_policy.alfa
tests/
```

## Testing

```bash
pytest -q
```
