# PostgreSQL-backed LangGraph checkpoint mediation

Scope: PAC++ New only. This is a provider-backed integration tranche, not a claim of complete agent-lifecycle protection.

## Provider adapter

PACAProvenancePostgresSaver wraps the official LangGraph PostgresSaver. It records an immutable PACA evidence object before each PostgreSQL checkpoint write and a distinct lineage-backed evidence object for each pending-write batch. A checkpoint update depends on the previously stored checkpoint; application-supplied provenance callbacks must supply all other trusted data dependencies for the checkpoint and each pending-write batch. After the provider returns, the adapter rechecks the checkpoint and every callback-supplied dependency under current lineage, authority, revocation and application policy. If revocation occurs during the PostgreSQL write, the provider row may already exist, but subsequent PAC++ reads fail before calling the provider; direct raw-provider access remains outside the wrapper.

Before returning checkpoint state, the wrapper authenticates the caller, retrieves the PACA evidence through TrustedMemoryAdapter, verifies lineage and authority, fetches the provider record, and compares the returned checkpoint and metadata with the stored evidence. It also verifies that the provider-returned checkpoint config is bound to the authenticated tenant-derived thread ID, namespace and expected checkpoint ID, and that any parent config points to a direct checkpoint parent in the immutable PACA lineage. Active authority and memory policy are rechecked after provider retrieval before the tuple is returned. It performs the same verification for pending writes, including a mediated read-back after provider writes. Checkpoint and pending-write operations are both mediated. Listing requires explicit tenant, thread and namespace scope; the wrapper preserves durable insertion chronology rather than sorting opaque checkpoint IDs, and a `before` cursor must belong to the same thread and namespace. Provider thread IDs are derived from the authenticated tenant and caller thread ID, avoiding collisions between tenants that choose the same external thread identifier.

Install the optional langgraph-postgres extra. Call setup() during trusted service startup to apply provider migrations. The CI service enables LANGGRAPH_STRICT_MSGPACK=true; production deployments should retain strict deserialization or configure an explicit safe module allow-list.

## Consistency and trust boundaries

PostgreSQL is the actual LangGraph checkpoint persistence provider. The PACA authority registry, provenance graph and evidence value store remain local SQLite databases. They do not share one atomic transaction or a distributed consensus protocol. Evidence is written before provider persistence; a provider failure can leave an evidence orphan, which the wrapper cannot release through its read path. The adapter has limited retry handling for pending-write persistence but no general cross-store recovery protocol.

This is not an unbypassable wrapper. A process retaining the raw PostgresSaver, PostgreSQL connection or database credentials can access provider data directly. Those objects and credentials must remain inside a trusted service/process and must not be exposed to agent-controlled code. The implementation uses the synchronous PostgresSaver and dispatches async saver methods to worker threads; it is not a native async connection-pool implementation. Mutable inputs to async wrapper methods are deep-copied before the worker-thread handoff so the provider operation sees the call-time snapshot; inputs that cannot be safely copied are rejected.

The PostgreSQL PendingWrite read contract returns three-tuples containing task ID, channel and value, without task_path. The adapter stores the task path in PACA evidence, uses it to reproduce provider ordering, and rejects reuse of one task ID across different paths within a checkpoint because the provider read tuple cannot distinguish those cases. Pending-write updates are immutable within a task/path/checkpoint identity. Thread deletion revokes both checkpoint evidence and the separately stored pending-write evidence before delegating provider deletion; the caller must hold explicit `mem_delete` scope for both evidence namespaces. The PostgreSQL integration suite verifies that pending-write evidence is revoked on deletion and that a source revoked during provider checkpoint persistence cannot subsequently be read through PAC++.

## Bounded lifecycle model

models/PACALifecycle.tla and its TLC configuration cover:
- memory, checkpoint and pending-write lineage with exact parent value/digest validation and non-empty dependencies;
- provider-returned checkpoint identity, namespace and parent-config binding; insertion-ordered checkpoint listing and same-thread cursor validation;
- pending-write evidence revocation when a checkpoint thread is deleted;
- delegated authority ancestry and attenuated grants;
- tenant, purpose and task continuity across derived data;
- lineage revocation, authority revocation, expiry and policy epochs;
- visibility only while complete lineage and authority chains remain live;
- one task-wide operation budget shared by delegated authorities; and
- an abstract remote effect that checks authority at the commit transition.

The finite state space is deliberately small. TLC checking establishes only that the abstract specification satisfies its listed invariants for the supplied constants. It is not a refinement proof for the Python implementation, proof of PostgreSQL/SQLite atomicity, host isolation, distributed registry consistency, or destination-side enforcement.

## Known omissions

No Gmail, Microsoft Graph, Slack or production vector-database connectors are implemented by this integration. The local fixture connector in the CI test is only a deterministic provenance source. The six security gates described in the lifecycle roadmap remain separate work items.
