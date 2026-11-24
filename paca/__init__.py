"""PACA++ - Provenance-Anchored Continuous Authorization for autonomous LLM agents."""
from .ast import EvaluationResult, Expression, Obligation, Policy, PolicySet, ProvenanceRecord
from .authority import AuthorityLineage, AuthorityLineageGraph
from .authority_runtime import (
    AuthorityRegistryError,
    CapabilityAuthenticationError,
    Ed25519CapabilityAuthority,
    HMACCapabilityAuthority,
    SignedCapability,
    VerifiedResourceCommitPermit,
    SQLiteAuthorityRegistry,
)
from .durable import (
    ImmutableLineageConflict,
    LineageIntegrityError,
    ProvenanceStoreError,
    SQLiteProvenanceRepository,
)
from .compiler import compile_policy, compile_policy_source
from .engine import PolicyEngine
from .evaluator import evaluate_policy, evaluate_policy_set
from .parser import parse_policy, parse_policy_file, parse_policy_set
from .provenance import Arg, Label, LineageNode, ProvenanceGraph, derive
from .memory import (
    HMACAgentMessageCodec,
    MemoryAccessContext,
    MemoryAccessDenied,
    MemoryIntegrityError,
    PACAAgentRuntime,
    SQLiteMemoryValueStore,
    TrustedConnectorAdapter,
    TrustedMemoryAdapter,
)
from .postgres_authority import PostgresAuthorityRegistry
from .sandbox import (
    DockerSandbox,
    DockerSandboxExecutor,
    SandboxError,
    SandboxExecutionError,
    SandboxOutputLimitExceeded,
    SandboxResult,
    SandboxTimeout,
    SandboxUnavailable,
)
from .resource_commit import ResourceCommitDenied, SQLiteFencedResourceExecutor

__version__ = "0.3.2"
__all__ = [n for n in dir() if not n.startswith("_")]
