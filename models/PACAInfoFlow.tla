---------------- MODULE PACAInfoFlow ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes, IntegrityLevels, SensitivityLevels, Declassifiers, DeclassifiableNodes,
    MaxSensitivity

VARIABLES
    nodeState, nodeParents, nodeIntegrity, nodeSensitivity, nodeDeclassified,
    nodeAuditRecorded, nodeDeclassActor

vars ==
    << nodeState, nodeParents, nodeIntegrity, nodeSensitivity, nodeDeclassified,
       nodeAuditRecorded, nodeDeclassActor >>

NodeStates == {"absent", "stored"}

RECURSIVE Ancestors(_)
Ancestors(n) ==
    IF nodeState[n] = "absent"
    THEN {}
    ELSE UNION { {p} \cup Ancestors(p) : p \in nodeParents[n] }

MaxSensitivityOf(deps) ==
    CHOOSE s \in SensitivityLevels:
        /\ \A p \in deps: nodeSensitivity[p] <= s
        /\ \E p \in deps: nodeSensitivity[p] = s

JoinIntegrity(deps) ==
    IF \E p \in deps: nodeIntegrity[p] = "untrusted"
    THEN "untrusted" ELSE "trusted"

Init ==
    /\ nodeState = [n \in Nodes |-> "absent"]
    /\ nodeParents = [n \in Nodes |-> {}]
    /\ nodeIntegrity = [n \in Nodes |-> CHOOSE i \in IntegrityLevels: TRUE]
    /\ nodeSensitivity = [n \in Nodes |-> 0]
    /\ nodeDeclassified = [n \in Nodes |-> FALSE]
    /\ nodeAuditRecorded = [n \in Nodes |-> FALSE]
    /\ nodeDeclassActor = [n \in Nodes |-> "NO_ACTOR"]

Ingest(n, integrity, sensitivity) ==
    /\ n \in Nodes
    /\ nodeState[n] = "absent"
    /\ integrity \in IntegrityLevels
    /\ sensitivity \in SensitivityLevels
    /\ nodeState' = [nodeState EXCEPT ![n] = "stored"]
    /\ nodeParents' = [nodeParents EXCEPT ![n] = {}]
    /\ nodeIntegrity' = [nodeIntegrity EXCEPT ![n] = integrity]
    /\ nodeSensitivity' = [nodeSensitivity EXCEPT ![n] = sensitivity]
    /\ UNCHANGED << nodeDeclassified, nodeAuditRecorded, nodeDeclassActor >>

Derive(n, deps) ==
    /\ n \in Nodes
    /\ nodeState[n] = "absent"
    /\ deps \subseteq Nodes
    /\ deps # {}
    /\ \A p \in deps: nodeState[p] = "stored"
    /\ nodeState' = [nodeState EXCEPT ![n] = "stored"]
    /\ nodeParents' = [nodeParents EXCEPT ![n] = deps]
    /\ nodeIntegrity' = [nodeIntegrity EXCEPT ![n] = JoinIntegrity(deps)]
    /\ nodeSensitivity' = [nodeSensitivity EXCEPT ![n] = MaxSensitivityOf(deps)]
    /\ nodeDeclassified' = [nodeDeclassified EXCEPT ![n] = FALSE]
    /\ nodeAuditRecorded' = [nodeAuditRecorded EXCEPT ![n] = FALSE]
    /\ nodeDeclassActor' = [nodeDeclassActor EXCEPT ![n] = "NO_ACTOR"]

Declassify(n, source, actor, newSensitivity) ==
    /\ n \in Nodes
    /\ source \in Nodes
    /\ nodeState[n] = "absent"
    /\ nodeState[source] = "stored"
    /\ actor \in Declassifiers
    /\ source \in DeclassifiableNodes
    /\ newSensitivity \in SensitivityLevels
    /\ newSensitivity < nodeSensitivity[source]
    /\ nodeState' = [nodeState EXCEPT ![n] = "stored"]
    /\ nodeParents' = [nodeParents EXCEPT ![n] = {source}]
    /\ nodeIntegrity' = [nodeIntegrity EXCEPT ![n] = nodeIntegrity[source]]
    /\ nodeSensitivity' = [nodeSensitivity EXCEPT ![n] = newSensitivity]
    /\ nodeDeclassified' = [nodeDeclassified EXCEPT ![n] = TRUE]
    /\ nodeAuditRecorded' = [nodeAuditRecorded EXCEPT ![n] = TRUE]
    /\ nodeDeclassActor' = [nodeDeclassActor EXCEPT ![n] = actor]

Next ==
    \/ \E n \in Nodes, integrity \in IntegrityLevels, sensitivity \in SensitivityLevels:
          Ingest(n, integrity, sensitivity)
    \/ \E n \in Nodes, deps \in SUBSET Nodes: Derive(n, deps)
    \/ \E n \in Nodes, source \in Nodes, actor \in Declassifiers,
          sensitivity \in SensitivityLevels:
          Declassify(n, source, actor, sensitivity)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ nodeState \in [Nodes -> NodeStates]
    /\ nodeParents \in [Nodes -> SUBSET Nodes]
    /\ nodeIntegrity \in [Nodes -> IntegrityLevels]
    /\ nodeSensitivity \in [Nodes -> SensitivityLevels]
    /\ nodeDeclassified \in [Nodes -> BOOLEAN]
    /\ nodeAuditRecorded \in [Nodes -> BOOLEAN]
    /\ nodeDeclassActor \in [Nodes -> (Declassifiers \cup {"NO_ACTOR"})]

LineageAcyclic ==
    \A n \in Nodes: n \notin Ancestors(n)

ParentsExist ==
    \A n \in Nodes:
        nodeState[n] = "stored" =>
            \A p \in nodeParents[n]: nodeState[p] = "stored"

NoIntegrityUpgrade ==
    \A n \in Nodes:
        nodeState[n] = "stored" =>
            (\E p \in nodeParents[n]: nodeIntegrity[p] = "untrusted")
            => nodeIntegrity[n] = "untrusted"

NoSilentSensitivityDowngrade ==
    \A n \in Nodes:
        nodeState[n] = "stored" /\ nodeParents[n] # {}
        /\ nodeSensitivity[n] < MaxSensitivityOf(nodeParents[n])
        => nodeDeclassified[n] /\ nodeAuditRecorded[n]

DeclassificationIsAudited ==
    \A n \in Nodes: nodeDeclassified[n] =>
        /\ nodeAuditRecorded[n]
        /\ nodeDeclassActor[n] \in Declassifiers
        /\ Cardinality(nodeParents[n]) = 1

DeclassificationDoesNotUpgradeIntegrity ==
    \A n \in Nodes:
        nodeDeclassified[n] =>
            \A p \in nodeParents[n]: nodeIntegrity[n] = nodeIntegrity[p]

====
