# Direct-bypass evaluation boundary

Scope: PAC++ New only. This is a boundary inventory and a set of deliberate negative controls. It does not claim that arbitrary agent execution is contained.

| Execution path | What the PACA adapter mediates | Direct bypass that remains |
|---|---|---|
| TrustedMemoryAdapter | Capability, tenant, purpose, lineage, authority and revocation checks before the value lookup | A caller with the raw SQLite value-store object or database file can read the stored value |
| LangGraph BaseStore integration | BaseStore operations explicitly routed through the PACA store; namespace metadata listing uses the same lineage, tenant, authority and application-policy checks without fetching value bytes; async store inputs are deep-copied before worker-thread handoff | A separate unwrapped BaseStore or checkpointer bypasses the adapter; runtime/context/store/config objects remain trusted dependencies |
| PostgreSQL checkpointer integration | Checkpoint and pending-write evidence before provider reads; provider/evidence comparison before state is returned | Direct PostgresSaver calls or SQL using raw credentials bypass the Python wrapper |
| LangChain middleware | Registered tool calls routed through middleware; JSON tool-call payload, graph state and registered manifest are checked, then the handler receives a request snapshot with copied tool-call data, tool identity and graph state | Direct calls to the Python tool function, direct Tool.invoke, alternate tool clients or another framework bypass the middleware; PACA must be the innermost/last tool-call middleware, runtime/context/store objects remain trusted dependencies, and the request factory's semantic mapping remains an application responsibility |
| PACAAgentRuntime | Lineage-bearing request arguments are checked against exact persisted value digests and conservative labels; resource references are checked against current lineage policy; an immutable request snapshot is used for the monitor and executor | Untracked arguments with no lineage refs depend on trusted ingress labels; arbitrary subprocesses and direct filesystem, database or network APIs are outside the Python monitor |
| Filesystem primitive | Linux `SecureRoot` uses `openat2` beneath an administrator-configured root and rejects symlinks, hard links, non-regular files and blocking FIFOs | This is only effective when every file operation uses the returned descriptor; direct filesystem APIs bypass it, and the root's mount/ownership/device configuration remains trusted |
| Remote effects | Local authority revalidation immediately before the configured executor | The destination must revalidate authorization at its own commit boundary |

## LangGraph tenant-key isolation

PACA LangGraph Store object identities are scoped by a digest of the tenant taken from the authenticated capability, in addition to the LangGraph namespace and key. Search and namespace enumeration traverse only that tenant's object prefix. Two tenants can therefore use the same namespace/key pair without sharing an immutable PACA object identity or blocking one another.

The updated identity format is intentionally not backward-compatible with previously stored unscoped `mem/langgraph/<encoded-namespace-and-key>` records. The adapter does not fall back to those IDs because their tenant ownership cannot be inferred safely from the key. Existing local records require an explicit, reviewed migration based on a trusted tenant mapping; where that mapping is unavailable, records must remain inaccessible rather than be assigned to a tenant by guesswork. Re-ingestion must preserve or reconstruct trusted source lineage.

## Deployment separation

Raw provider objects, SQLite files, HMAC issuer material, database connections and connector credentials belong in a trusted process or service that the agent cannot introspect. The agent-facing API should expose only authenticated PACA operations. Database roles should prevent agent identities from reading checkpoint, write, blob and evidence tables or writing outside the mediator. Tool implementations should run in an explicitly instrumented and OS-constrained worker. Python middleware is not an operating-system security boundary.

## Test interpretation

The lifecycle suite includes a negative control proving that direct use of the raw SQLite value store bypasses the memory adapter. The PostgreSQL integration test similarly demonstrates that a caller retaining the raw checkpointer can read state after the PACA wrapper denies it. The bypass matrix also shows that direct subprocess/filesystem and direct LangChain Tool.invoke calls do not enter the middleware path. These tests are intentional boundary demonstrations, not successful enforcement tests.

The mediated counterpart tests assert that a revoked source is rejected before the PostgreSQL provider is called, an application memory policy denying a stored object also denies namespace metadata disclosure, async BaseStore and PostgreSQL checkpoint calls snapshot mutable inputs before worker-thread handoff, inter-agent envelopes reject values whose bytes do not match their immutable lineage digest, effect requests cannot reuse a source reference for different argument bytes or weaker labels, and LangChain middleware refuses tool-call or graph-state mutation during request construction and after authorization, and gives asynchronous handlers a copied request/state so caller-side mutation during suspension does not change the executed arguments or state snapshot. A full host-level bypass assessment still requires a separate process/container boundary, attacker-controlled code, host-private storage, distinct identities and credentials, and tests against direct filesystem, database and network sinks.
