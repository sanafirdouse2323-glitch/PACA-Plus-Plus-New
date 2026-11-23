---------------- MODULE PACALifecycle ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes, Authorities, Tenants, Purposes, Tasks, Actions,
    NoAuthority, NoTenant, NoPurpose, MaxTaskCalls,
    RootAuthority, RootTenant, RootPurpose, RootTask, RootGrants

NoTask == "NO_TASK"
NodeStates == {"absent", "stored", "revoked"}
NodeKinds == {"none", "memory", "checkpoint", "pending_write"}
AuthorityStates == {"absent", "active", "revoked", "expired"}
EpochValues == {-1, 0, 1}
PolicyEpochValues == {0, 1}

VARIABLES
    nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
    nodeTask, nodeAuthority, visible,
    authorityState, authorityParent, authorityTenant,
    authorityPurpose, authorityTask, authorityEpoch, authorityGrants,
    policyEpoch, taskCalls, effectsCommitted, effectAuthorizedAtCommit

vars ==
    << nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
       nodeTask, nodeAuthority, visible, authorityState, authorityParent,
       authorityTenant, authorityPurpose, authorityTask, authorityEpoch,
       authorityGrants, policyEpoch, taskCalls, effectsCommitted,
       effectAuthorizedAtCommit >>

RECURSIVE Ancestors(_), AuthorityChainActive(_), AuthorityDescendsFrom(_, _)

Ancestors(n) ==
    IF nodeState[n] = "absent"
    THEN {}
    ELSE UNION { {p} \cup Ancestors(p) : p \in nodeParents[n] }

AuthorityChainActive(a) ==
    IF a \notin Authorities
    THEN FALSE
    ELSE
        /\ authorityState[a] = "active"
        /\ authorityEpoch[a] = policyEpoch
        /\ (authorityParent[a] = NoAuthority
            \/ AuthorityChainActive(authorityParent[a]))

AuthorityDescendsFrom(candidate, ancestor) ==
    IF candidate \notin Authorities
    THEN FALSE
    ELSE
        candidate = ancestor
        \/ (authorityParent[candidate] # NoAuthority
            /\ AuthorityDescendsFrom(authorityParent[candidate], ancestor))

LineageLive(n) ==
    /\ nodeState[n] = "stored"
    /\ \A p \in Ancestors(n): nodeState[p] = "stored"

LineageAuthorityLive(n) ==
    \A p \in ({n} \cup Ancestors(n)):
        AuthorityChainActive(nodeAuthority[p])

LineageScopeMatches(n, a) ==
    \A p \in ({n} \cup Ancestors(n)):
        /\ nodeTenant[p] = authorityTenant[a]
        /\ nodePurpose[p] = authorityPurpose[a]
        /\ nodeTask[p] = authorityTask[a]

Init ==
    /\ nodeState = [n \in Nodes |-> "absent"]
    /\ nodeKind = [n \in Nodes |-> "none"]
    /\ nodeParents = [n \in Nodes |-> {}]
    /\ nodeTenant = [n \in Nodes |-> NoTenant]
    /\ nodePurpose = [n \in Nodes |-> NoPurpose]
    /\ nodeTask = [n \in Nodes |-> NoTask]
    /\ nodeAuthority = [n \in Nodes |-> NoAuthority]
    /\ visible = [n \in Nodes |-> FALSE]
    /\ authorityState = [a \in Authorities |->
        IF a = RootAuthority THEN "active" ELSE "absent"]
    /\ authorityParent = [a \in Authorities |-> NoAuthority]
    /\ authorityTenant = [a \in Authorities |->
        IF a = RootAuthority THEN RootTenant ELSE NoTenant]
    /\ authorityPurpose = [a \in Authorities |->
        IF a = RootAuthority THEN RootPurpose ELSE NoPurpose]
    /\ authorityTask = [a \in Authorities |->
        IF a = RootAuthority THEN RootTask ELSE NoTask]
    /\ authorityEpoch = [a \in Authorities |->
        IF a = RootAuthority THEN 0 ELSE -1]
    /\ authorityGrants = [a \in Authorities |->
        IF a = RootAuthority THEN RootGrants ELSE {}]
    /\ policyEpoch = 0
    /\ taskCalls = [t \in Tasks |-> 0]
    /\ effectsCommitted = [n \in Nodes |-> 0]
    /\ effectAuthorizedAtCommit = [n \in Nodes |-> FALSE]

Ingest(n, a) ==
    /\ n \in Nodes
    /\ a \in Authorities
    /\ nodeState[n] = "absent"
    /\ AuthorityChainActive(a)
    /\ "memWrite" \in authorityGrants[a]
    /\ taskCalls[authorityTask[a]] < MaxTaskCalls
    /\ nodeState' = [nodeState EXCEPT ![n] = "stored"]
    /\ nodeKind' = [nodeKind EXCEPT ![n] = "memory"]
    /\ nodeParents' = [nodeParents EXCEPT ![n] = {}]
    /\ nodeTenant' = [nodeTenant EXCEPT ![n] = authorityTenant[a]]
    /\ nodePurpose' = [nodePurpose EXCEPT ![n] = authorityPurpose[a]]
    /\ nodeTask' = [nodeTask EXCEPT ![n] = authorityTask[a]]
    /\ nodeAuthority' = [nodeAuthority EXCEPT ![n] = a]
    /\ taskCalls' = [taskCalls EXCEPT ![authorityTask[a]] = @ + 1]
    /\ UNCHANGED
        << visible, authorityState, authorityParent, authorityTenant,
           authorityPurpose, authorityTask, authorityEpoch, authorityGrants,
           policyEpoch, effectsCommitted, effectAuthorizedAtCommit >>

Derive(n, deps, a, kind) ==
    /\ n \in Nodes
    /\ deps \subseteq Nodes
    /\ deps # {}
    /\ kind \in {"memory", "checkpoint", "pending_write"}
    /\ a \in Authorities
    /\ nodeState[n] = "absent"
    /\ AuthorityChainActive(a)
    /\ IF kind = "checkpoint"
          THEN "checkpointWrite" \in authorityGrants[a]
          ELSE "memWrite" \in authorityGrants[a]
    /\ IF kind = "pending_write"
          THEN \E p \in deps: nodeKind[p] = "checkpoint"
          ELSE TRUE
    /\ taskCalls[authorityTask[a]] < MaxTaskCalls
    /\ \A p \in deps: LineageLive(p)
    /\ \A p \in deps: LineageAuthorityLive(p)
    /\ \A p \in deps: LineageScopeMatches(p, a)
    /\ nodeState' = [nodeState EXCEPT ![n] = "stored"]
    /\ nodeKind' = [nodeKind EXCEPT ![n] = kind]
    /\ nodeParents' = [nodeParents EXCEPT ![n] = deps]
    /\ nodeTenant' = [nodeTenant EXCEPT ![n] = authorityTenant[a]]
    /\ nodePurpose' = [nodePurpose EXCEPT ![n] = authorityPurpose[a]]
    /\ nodeTask' = [nodeTask EXCEPT ![n] = authorityTask[a]]
    /\ nodeAuthority' = [nodeAuthority EXCEPT ![n] = a]
    /\ taskCalls' = [taskCalls EXCEPT ![authorityTask[a]] = @ + 1]
    /\ UNCHANGED
        << visible, authorityState, authorityParent, authorityTenant,
           authorityPurpose, authorityTask, authorityEpoch, authorityGrants,
           policyEpoch, effectsCommitted, effectAuthorizedAtCommit >>

WriteCheckpoint(n, deps, a) ==
    Derive(n, deps, a, "checkpoint")

WritePendingWrites(n, deps, a) ==
    Derive(n, deps, a, "pending_write")

Delegate(child, parent, grants) ==
    /\ child \in Authorities
    /\ parent \in Authorities
    /\ child # parent
    /\ authorityState[child] = "absent"
    /\ AuthorityChainActive(parent)
    /\ grants \subseteq authorityGrants[parent]
    /\ taskCalls[authorityTask[parent]] < MaxTaskCalls
    /\ authorityState' = [authorityState EXCEPT ![child] = "active"]
    /\ authorityParent' = [authorityParent EXCEPT ![child] = parent]
    /\ authorityTenant' = [authorityTenant EXCEPT ![child] = authorityTenant[parent]]
    /\ authorityPurpose' = [authorityPurpose EXCEPT ![child] = authorityPurpose[parent]]
    /\ authorityTask' = [authorityTask EXCEPT ![child] = authorityTask[parent]]
    /\ authorityEpoch' = [authorityEpoch EXCEPT ![child] = policyEpoch]
    /\ authorityGrants' = [authorityGrants EXCEPT ![child] = grants]
    /\ taskCalls' = [taskCalls EXCEPT ![authorityTask[parent]] = @ + 1]
    /\ UNCHANGED
        << nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
           nodeTask, nodeAuthority, visible, policyEpoch, effectsCommitted,
           effectAuthorizedAtCommit >>

ReadMemory(n, a) ==
    /\ n \in Nodes
    /\ a \in Authorities
    /\ nodeKind[n] \in {"memory", "checkpoint", "pending_write"}
    /\ "memRead" \in authorityGrants[a]
    /\ LineageLive(n)
    /\ LineageAuthorityLive(n)
    /\ AuthorityChainActive(a)
    /\ LineageScopeMatches(n, a)
    /\ taskCalls[authorityTask[a]] < MaxTaskCalls
    /\ visible' = [visible EXCEPT ![n] = TRUE]
    /\ taskCalls' = [taskCalls EXCEPT ![authorityTask[a]] = @ + 1]
    /\ UNCHANGED
        << nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
           nodeTask, nodeAuthority, authorityState, authorityParent,
           authorityTenant, authorityPurpose, authorityTask, authorityEpoch,
           authorityGrants, policyEpoch, effectsCommitted,
           effectAuthorizedAtCommit >>

RevokeLineage(n) ==
    /\ n \in Nodes
    /\ nodeState[n] = "stored"
    /\ nodeState' = [nodeState EXCEPT ![n] = "revoked"]
    /\ visible' = [x \in Nodes |->
        IF x = n \/ n \in Ancestors(x) THEN FALSE ELSE visible[x]]
    /\ UNCHANGED
        << nodeKind, nodeParents, nodeTenant, nodePurpose, nodeTask,
           nodeAuthority, authorityState, authorityParent, authorityTenant,
           authorityPurpose, authorityTask, authorityEpoch, authorityGrants,
           policyEpoch, taskCalls, effectsCommitted, effectAuthorizedAtCommit >>

RevokeAuthority(a) ==
    /\ a \in Authorities
    /\ authorityState[a] = "active"
    /\ authorityState' = [candidate \in Authorities |->
        IF AuthorityDescendsFrom(candidate, a)
        THEN "revoked" ELSE authorityState[candidate]]
    /\ visible' = [n \in Nodes |->
        IF \E p \in ({n} \cup Ancestors(n)):
            nodeState[p] = "stored"
            /\ AuthorityDescendsFrom(nodeAuthority[p], a)
        THEN FALSE ELSE visible[n]]
    /\ UNCHANGED
        << nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
           nodeTask, nodeAuthority, authorityParent, authorityTenant,
           authorityPurpose, authorityTask, authorityEpoch, authorityGrants,
           policyEpoch, taskCalls, effectsCommitted, effectAuthorizedAtCommit >>

ExpireAuthority(a) ==
    /\ a \in Authorities
    /\ authorityState[a] = "active"
    /\ authorityState' = [authorityState EXCEPT ![a] = "expired"]
    /\ visible' = [n \in Nodes |->
        IF \E p \in ({n} \cup Ancestors(n)):
            nodeState[p] = "stored"
            /\ AuthorityDescendsFrom(nodeAuthority[p], a)
        THEN FALSE ELSE visible[n]]
    /\ UNCHANGED
        << nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
           nodeTask, nodeAuthority, authorityParent, authorityTenant,
           authorityPurpose, authorityTask, authorityEpoch, authorityGrants,
           policyEpoch, taskCalls, effectsCommitted, effectAuthorizedAtCommit >>

AdvancePolicyEpoch ==
    /\ policyEpoch = 0
    /\ policyEpoch' = 1
    /\ visible' = [n \in Nodes |-> FALSE]
    /\ UNCHANGED
        << nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
           nodeTask, nodeAuthority, authorityState, authorityParent,
           authorityTenant, authorityPurpose, authorityTask, authorityEpoch,
           authorityGrants, taskCalls, effectsCommitted, effectAuthorizedAtCommit >>

CommitRemoteEffect(n, a) ==
    /\ n \in Nodes
    /\ a \in Authorities
    /\ "toolCall" \in authorityGrants[a]
    /\ LineageLive(n)
    /\ LineageAuthorityLive(n)
    /\ AuthorityChainActive(a)
    /\ LineageScopeMatches(n, a)
    /\ taskCalls[authorityTask[a]] < MaxTaskCalls
    /\ effectsCommitted' = [effectsCommitted EXCEPT ![n] = @ + 1]
    /\ effectAuthorizedAtCommit' = [effectAuthorizedAtCommit EXCEPT ![n] = TRUE]
    /\ taskCalls' = [taskCalls EXCEPT ![authorityTask[a]] = @ + 1]
    /\ UNCHANGED
        << nodeState, nodeKind, nodeParents, nodeTenant, nodePurpose,
           nodeTask, nodeAuthority, visible, authorityState, authorityParent,
           authorityTenant, authorityPurpose, authorityTask, authorityEpoch,
           authorityGrants, policyEpoch >>

Next ==
    \/ \E n \in Nodes, a \in Authorities: Ingest(n, a)
    \/ \E n \in Nodes, deps \in SUBSET Nodes, a \in Authorities:
        WriteCheckpoint(n, deps, a)
    \/ \E n \in Nodes, deps \in SUBSET Nodes, a \in Authorities:
        WritePendingWrites(n, deps, a)
    \/ \E child \in Authorities, parent \in Authorities,
          grants \in SUBSET Actions: Delegate(child, parent, grants)
    \/ \E n \in Nodes, a \in Authorities: ReadMemory(n, a)
    \/ \E n \in Nodes: RevokeLineage(n)
    \/ \E a \in Authorities: RevokeAuthority(a)
    \/ \E a \in Authorities: ExpireAuthority(a)
    \/ AdvancePolicyEpoch
    \/ \E n \in Nodes, a \in Authorities: CommitRemoteEffect(n, a)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ nodeState \in [Nodes -> NodeStates]
    /\ nodeKind \in [Nodes -> NodeKinds]
    /\ nodeParents \in [Nodes -> SUBSET Nodes]
    /\ nodeTenant \in [Nodes -> (Tenants \cup {NoTenant})]
    /\ nodePurpose \in [Nodes -> (Purposes \cup {NoPurpose})]
    /\ nodeTask \in [Nodes -> (Tasks \cup {NoTask})]
    /\ nodeAuthority \in [Nodes -> (Authorities \cup {NoAuthority})]
    /\ visible \in [Nodes -> BOOLEAN]
    /\ authorityState \in [Authorities -> AuthorityStates]
    /\ authorityParent \in [Authorities -> (Authorities \cup {NoAuthority})]
    /\ authorityTenant \in [Authorities -> (Tenants \cup {NoTenant})]
    /\ authorityPurpose \in [Authorities -> (Purposes \cup {NoPurpose})]
    /\ authorityTask \in [Authorities -> (Tasks \cup {NoTask})]
    /\ authorityEpoch \in [Authorities -> EpochValues]
    /\ authorityGrants \in [Authorities -> SUBSET Actions]
    /\ policyEpoch \in PolicyEpochValues
    /\ taskCalls \in [Tasks -> 0..MaxTaskCalls]
    /\ effectsCommitted \in [Nodes -> 0..MaxTaskCalls]
    /\ effectAuthorizedAtCommit \in [Nodes -> BOOLEAN]

LineageAcyclic ==
    \A n \in Nodes: n \notin Ancestors(n)

CheckpointHasCompleteLineage ==
    \A n \in Nodes:
        nodeState[n] = "stored" /\ nodeKind[n] = "checkpoint"
        => nodeParents[n] # {}

PendingWriteBoundToCheckpoint ==
    \A n \in Nodes:
        nodeState[n] = "stored" /\ nodeKind[n] = "pending_write"
        => \E p \in nodeParents[n]: nodeKind[p] = "checkpoint"

VisibleRequiresActiveLineageAndAuthority ==
    \A n \in Nodes:
        visible[n] =>
            /\ LineageLive(n)
            /\ LineageAuthorityLive(n)
            /\ \A p \in ({n} \cup Ancestors(n)):
                authorityEpoch[nodeAuthority[p]] = policyEpoch

TaskQuotaBounded ==
    \A t \in Tasks: taskCalls[t] <= MaxTaskCalls

DelegationIsAttenuated ==
    \A a \in Authorities:
        authorityParent[a] # NoAuthority =>
            authorityGrants[a] \subseteq authorityGrants[authorityParent[a]]

EffectsRequireCommitBoundaryAuthorization ==
    \A n \in Nodes:
        effectsCommitted[n] > 0 => effectAuthorizedAtCommit[n]

====
