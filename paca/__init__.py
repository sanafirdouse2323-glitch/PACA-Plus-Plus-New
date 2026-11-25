"""PACA++ - Provenance-Anchored Continuous Authorization for autonomous LLM agents."""

from .ast import (
    EvaluationResult,
    Expression,
    Obligation,
    Policy,
    PolicySet,
    ProvenanceRecord,
)
from .authority import AuthorityLineage, AuthorityLineageGraph
from .authority_runtime import (
    AuthorityRegistryError,
    CapabilityAuthenticationError,
    Ed25519CapabilityAuthority,
    HMACCapabilityAuthority,
    SignedCapability,
    SQLiteAuthorityRegistry,
    VerifiedResourceCommitPermit,
)
from .broker import BrokerResourceDenied, InProcessBrokerReadMediator
from .broker_write import InProcessBrokerWriteMediator
from .compiler import compile_policy, compile_policy_source
from .durable import (
    ImmutableLineageConflict,
    LineageIntegrityError,
    ProvenanceStoreError,
    SQLiteProvenanceRepository,
)
from .engine import PolicyEngine
from .evaluator import evaluate_policy, evaluate_policy_set
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
from .parser import parse_policy, parse_policy_file, parse_policy_set
from .postgres_authority import PostgresAuthorityRegistry
from .provenance import Arg, Label, LineageNode, ProvenanceGraph, derive
from .resource_commit import (
    FencedResourceExecutor,
    ResourceCommitDenied,
    SQLiteFencedResourceExecutor,
)
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

__version__ = "0.3.2"
__all__ = [
    "Arg",
    "AuthorityLineage",
    "AuthorityLineageGraph",
    "AuthorityRegistryError",
    "BrokerResourceDenied",
    "CapabilityAuthenticationError",
    "DockerSandbox",
    "DockerSandboxExecutor",
    "Ed25519CapabilityAuthority",
    "EvaluationResult",
    "FencedResourceExecutor",
    "Expression",
    "HMACAgentMessageCodec",
    "HMACCapabilityAuthority",
    "InProcessBrokerReadMediator",
    "InProcessBrokerWriteMediator",
    "ImmutableLineageConflict",
    "Label",
    "LineageIntegrityError",
    "LineageNode",
    "MemoryAccessContext",
    "MemoryAccessDenied",
    "MemoryIntegrityError",
    "Obligation",
    "PACAAgentRuntime",
    "Policy",
    "PolicyEngine",
    "PolicySet",
    "PostgresAuthorityRegistry",
    "ProvenanceGraph",
    "ProvenanceRecord",
    "ProvenanceStoreError",
    "ResourceCommitDenied",
    "SQLiteAuthorityRegistry",
    "SQLiteFencedResourceExecutor",
    "SQLiteMemoryValueStore",
    "SQLiteProvenanceRepository",
    "SandboxError",
    "SandboxExecutionError",
    "SandboxOutputLimitExceeded",
    "SandboxResult",
    "SandboxTimeout",
    "SandboxUnavailable",
    "SignedCapability",
    "TrustedConnectorAdapter",
    "TrustedMemoryAdapter",
    "VerifiedResourceCommitPermit",
    "__version__",
    "compile_policy",
    "compile_policy_source",
    "derive",
    "evaluate_policy",
    "evaluate_policy_set",
    "parse_policy",
    "parse_policy_file",
    "parse_policy_set",
]
