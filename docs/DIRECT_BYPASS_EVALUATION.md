# Direct-bypass evaluation boundary

Scope: PACA++ New only. This is a boundary inventory and a set of deliberate negative controls. It does not claim that arbitrary agent execution is contained.

| Execution path | What the PACA adapter mediates | Direct bypass that remains |
|---|---|---|
| TrustedMemoryAdapter | Capability, tenant, purpose, lineage, authority and revocation checks before the value lookup | A caller with the raw SQLite value-store object or database file can read the stored value |
| LangGraph BaseStore integration | BaseStore operations explicitly routed through the PACA store | A separate unwrapped BaseStore or checkpointer bypasses the adapter |
| PostgreSQL checkpointer integration | Checkpoint and pending-write evidence before provider reads; provider/evidence comparison before state is returned | Direct PostgresSaver calls or SQL using raw credentials bypass the Python wrapper |
| LangChain middleware | Registered tool calls routed through the middleware hooks | Direct calls to the Python tool function, direct Tool.invoke, alternate tool clients or another framework bypass the middleware |
| PACAAgentRuntime | The executor callback explicitly submitted through the PACA runtime | Arbitrary subprocesses and direct filesystem, database or network APIs are outside the Python monitor |
| Remote effects | Local authority revalidation immediately before the configured executor | The destination must revalidate authorization at its own commit boundary |

## LangGraph tenant-key isolation

PACA LangGraph Store object identities are scoped by a digest of the tenant taken from the authenticated capability, in addition to the LangGraph namespace and key. Search and namespace enumeration traverse only that tenant's object prefix. Two tenants can therefore use the same namespace/key pair without sharing an immutable PACA object identity or blocking one another.

The updated identity format is intentionally not backward-compatible with previously stored unscoped `mem/langgraph/<encoded-namespace-and-key>` records. The adapter does not fall back to those IDs because their tenant ownership cannot be inferred safely from the key. Existing local records require an explicit, reviewed migration based on a trusted tenant mapping; where that mapping is unavailable, records must remain inaccessible rather than be assigned to a tenant by guesswork. Re-ingestion must preserve or reconstruct trusted source lineage.

## Deployment separation

Raw provider objects, SQLite files, HMAC issuer material, database connections and connector credentials belong in a trusted process or service that the agent cannot introspect. The agent-facing API should expose only authenticated PACA operations. Database roles should prevent agent identities from reading checkpoint, write, blob and evidence tables or writing outside the mediator. Tool implementations should run in an explicitly instrumented and OS-constrained worker. Python middleware is not an operating-system security boundary.

## Test interpretation

The lifecycle suite includes a negative control proving that direct use of the raw SQLite value store bypasses the memory adapter. The PostgreSQL integration test similarly demonstrates that a caller retaining the raw checkpointer can read state after the PACA wrapper denies it. The bypass matrix also shows that direct subprocess/filesystem and direct LangChain Tool.invoke calls do not enter the middleware path. These tests are intentional boundary demonstrations, not successful enforcement tests.

The mediated counterpart tests assert that a revoked source is rejected before the PostgreSQL provider is called, and that an unauthorized LangChain middleware decision does not invoke its handler. A full host-level bypass assessment still requires a separate process/container boundary, attacker-controlled code, host-private storage, distinct identities and credentials, and tests against direct filesystem, database and network sinks.
