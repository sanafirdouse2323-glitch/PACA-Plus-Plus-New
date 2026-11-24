---------------- MODULE PACABroker ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Ops, ReadOp, WriteOp,
    TrustedPrincipal, AttackerPrincipal, Tenant, Task, Audience,
    ExpectedTarget, GoodArgsDigest, GoodPayloadDigest, BadDigest,
    NoValue, NoDigest, MaxOperations

VARIABLES
    sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
    claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
    requestPayloadDigest, operationState, permitState, permitTarget,
    permitArgsDigest, permitPayloadDigest, permitEpoch, policyEpoch, grantEpoch,
    grantRevoked, grantUses, readReleased, readAuthAtDisclosure, readEpoch,
    effectCount, effectAuthorizedAtCommit, effectTarget, effectArgsDigest,
    effectPayloadDigest, effectEpoch

vars ==
    << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
       claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
       requestPayloadDigest, operationState, permitState, permitTarget,
       permitArgsDigest, permitPayloadDigest, permitEpoch, policyEpoch, grantEpoch,
       grantRevoked, grantUses, readReleased, readAuthAtDisclosure, readEpoch,
       effectCount, effectAuthorizedAtCommit, effectTarget, effectArgsDigest,
       effectPayloadDigest, effectEpoch >>

OperationStates == {"new", "authorised", "permit_issued", "read_released", "committed", "denied"}
PermitStates == {"absent", "issued", "consumed", "invalidated"}
ActionNames == {"read", "write"}

Init ==
    /\ sessionValid = [op \in Ops |-> TRUE]
    /\ sessionPrincipal = [op \in Ops |-> TrustedPrincipal]
    /\ sessionTenant = [op \in Ops |-> Tenant]
    /\ sessionTask = [op \in Ops |-> Task]
    /\ sessionAudience = [op \in Ops |-> Audience]
    /\ claimedPrincipal = [op \in Ops |-> AttackerPrincipal]
    /\ opPrincipal = [op \in Ops |-> NoValue]
    /\ opAction = [op \in Ops |-> IF op = ReadOp THEN "read" ELSE "write"]
    /\ requestTarget = [op \in Ops |-> ExpectedTarget]
    /\ requestArgsDigest = [op \in Ops |-> GoodArgsDigest]
    /\ requestPayloadDigest = [op \in Ops |-> IF op = WriteOp THEN GoodPayloadDigest ELSE NoDigest]
    /\ operationState = [op \in Ops |-> "new"]
    /\ permitState = [op \in Ops |-> "absent"]
    /\ permitTarget = [op \in Ops |-> NoValue]
    /\ permitArgsDigest = [op \in Ops |-> NoDigest]
    /\ permitPayloadDigest = [op \in Ops |-> NoDigest]
    /\ permitEpoch = [op \in Ops |-> 0]
    /\ policyEpoch = 0
    /\ grantEpoch = 0
    /\ grantRevoked = FALSE
    /\ grantUses = 0
    /\ readReleased = [op \in Ops |-> FALSE]
    /\ readAuthAtDisclosure = [op \in Ops |-> FALSE]
    /\ readEpoch = [op \in Ops |-> 0]
    /\ effectCount = [op \in Ops |-> 0]
    /\ effectAuthorizedAtCommit = [op \in Ops |-> FALSE]
    /\ effectTarget = [op \in Ops |-> NoValue]
    /\ effectArgsDigest = [op \in Ops |-> NoDigest]
    /\ effectPayloadDigest = [op \in Ops |-> NoDigest]
    /\ effectEpoch = [op \in Ops |-> 0]

Authorize(op) ==
    /\ op \in Ops
    /\ operationState[op] = "new"
    /\ sessionValid[op]
    /\ sessionPrincipal[op] = TrustedPrincipal
    /\ sessionTenant[op] = Tenant
    /\ sessionTask[op] = Task
    /\ sessionAudience[op] = Audience
    /\ ~grantRevoked
    /\ policyEpoch = grantEpoch
    /\ opAction[op] \in ActionNames
    /\ requestTarget[op] = ExpectedTarget
    /\ requestArgsDigest[op] = GoodArgsDigest
    /\ grantUses < MaxOperations
    /\ opPrincipal' = [opPrincipal EXCEPT ![op] = sessionPrincipal[op]]
    /\ operationState' = [operationState EXCEPT ![op] = "authorised"]
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opAction, requestTarget, requestArgsDigest, requestPayloadDigest,
           permitState, permitTarget, permitArgsDigest, permitPayloadDigest, permitEpoch,
           policyEpoch, grantEpoch, grantRevoked, grantUses, readReleased,
           readAuthAtDisclosure, readEpoch, effectCount, effectAuthorizedAtCommit,
           effectTarget, effectArgsDigest, effectPayloadDigest, effectEpoch >>

IssueCommitPermit(op) ==
    /\ op \in Ops
    /\ opAction[op] = "write"
    /\ operationState[op] = "authorised"
    /\ permitState[op] = "absent"
    /\ ~grantRevoked
    /\ policyEpoch = grantEpoch
    /\ requestTarget[op] = ExpectedTarget
    /\ requestArgsDigest[op] = GoodArgsDigest
    /\ requestPayloadDigest[op] = GoodPayloadDigest
    /\ grantUses < MaxOperations
    /\ permitState' = [permitState EXCEPT ![op] = "issued"]
    /\ permitTarget' = [permitTarget EXCEPT ![op] = requestTarget[op]]
    /\ permitArgsDigest' = [permitArgsDigest EXCEPT ![op] = requestArgsDigest[op]]
    /\ permitPayloadDigest' = [permitPayloadDigest EXCEPT ![op] = requestPayloadDigest[op]]
    /\ permitEpoch' = [permitEpoch EXCEPT ![op] = policyEpoch]
    /\ operationState' = [operationState EXCEPT ![op] = "permit_issued"]
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
           requestPayloadDigest, policyEpoch, grantEpoch, grantRevoked, grantUses,
           readReleased, readAuthAtDisclosure, readEpoch, effectCount,
           effectAuthorizedAtCommit, effectTarget, effectArgsDigest, effectPayloadDigest,
           effectEpoch >>

MutateRequestAfterPermit(op) ==
    /\ op = WriteOp
    /\ permitState[op] = "issued"
    /\ requestPayloadDigest[op] = GoodPayloadDigest
    /\ requestPayloadDigest' = [requestPayloadDigest EXCEPT ![op] = BadDigest]
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
           operationState, permitState, permitTarget, permitArgsDigest, permitPayloadDigest,
           permitEpoch, policyEpoch, grantEpoch, grantRevoked, grantUses, readReleased,
           readAuthAtDisclosure, readEpoch, effectCount, effectAuthorizedAtCommit,
           effectTarget, effectArgsDigest, effectPayloadDigest, effectEpoch >>

RejectMismatchedCommit(op) ==
    /\ op \in Ops
    /\ permitState[op] = "issued"
    /\ (requestTarget[op] # permitTarget[op]
        \/ requestArgsDigest[op] # permitArgsDigest[op]
        \/ requestPayloadDigest[op] # permitPayloadDigest[op])
    /\ permitState' = [permitState EXCEPT ![op] = "invalidated"]
    /\ operationState' = [operationState EXCEPT ![op] = "denied"]
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
           requestPayloadDigest, permitTarget, permitArgsDigest, permitPayloadDigest,
           permitEpoch, policyEpoch, grantEpoch, grantRevoked, grantUses, readReleased,
           readAuthAtDisclosure, readEpoch, effectCount, effectAuthorizedAtCommit,
           effectTarget, effectArgsDigest, effectPayloadDigest, effectEpoch >>

CommitWrite(op) ==
    /\ op \in Ops
    /\ opAction[op] = "write"
    /\ operationState[op] = "permit_issued"
    /\ permitState[op] = "issued"
    /\ ~grantRevoked
    /\ policyEpoch = grantEpoch
    /\ permitEpoch[op] = policyEpoch
    /\ sessionValid[op]
    /\ sessionPrincipal[op] = opPrincipal[op]
    /\ sessionTenant[op] = Tenant
    /\ sessionTask[op] = Task
    /\ sessionAudience[op] = Audience
    /\ requestTarget[op] = permitTarget[op]
    /\ requestArgsDigest[op] = permitArgsDigest[op]
    /\ requestPayloadDigest[op] = permitPayloadDigest[op]
    /\ grantUses < MaxOperations
    /\ permitState' = [permitState EXCEPT ![op] = "consumed"]
    /\ operationState' = [operationState EXCEPT ![op] = "committed"]
    /\ grantUses' = grantUses + 1
    /\ effectCount' = [effectCount EXCEPT ![op] = @ + 1]
    /\ effectAuthorizedAtCommit' = [effectAuthorizedAtCommit EXCEPT ![op] = TRUE]
    /\ effectTarget' = [effectTarget EXCEPT ![op] = requestTarget[op]]
    /\ effectArgsDigest' = [effectArgsDigest EXCEPT ![op] = requestArgsDigest[op]]
    /\ effectPayloadDigest' = [effectPayloadDigest EXCEPT ![op] = requestPayloadDigest[op]]
    /\ effectEpoch' = [effectEpoch EXCEPT ![op] = policyEpoch]
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
           requestPayloadDigest, permitTarget, permitArgsDigest, permitPayloadDigest,
           permitEpoch, policyEpoch, grantEpoch, grantRevoked, readReleased,
           readAuthAtDisclosure, readEpoch >>

ReleaseRead(op) ==
    /\ op \in Ops
    /\ opAction[op] = "read"
    /\ operationState[op] = "authorised"
    /\ ~grantRevoked
    /\ policyEpoch = grantEpoch
    /\ sessionValid[op]
    /\ sessionPrincipal[op] = opPrincipal[op]
    /\ sessionTenant[op] = Tenant
    /\ sessionTask[op] = Task
    /\ sessionAudience[op] = Audience
    /\ requestTarget[op] = ExpectedTarget
    /\ requestArgsDigest[op] = GoodArgsDigest
    /\ grantUses < MaxOperations
    /\ readReleased' = [readReleased EXCEPT ![op] = TRUE]
    /\ readAuthAtDisclosure' = [readAuthAtDisclosure EXCEPT ![op] = TRUE]
    /\ readEpoch' = [readEpoch EXCEPT ![op] = policyEpoch]
    /\ operationState' = [operationState EXCEPT ![op] = "read_released"]
    /\ grantUses' = grantUses + 1
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
           requestPayloadDigest, permitState, permitTarget, permitArgsDigest,
           permitPayloadDigest, permitEpoch, policyEpoch, grantEpoch, grantRevoked,
           effectCount, effectAuthorizedAtCommit, effectTarget, effectArgsDigest,
           effectPayloadDigest, effectEpoch >>

RevokeGrant ==
    /\ ~grantRevoked
    /\ grantRevoked' = TRUE
    /\ permitState' = [op \in Ops |-> IF permitState[op] = "issued" THEN "invalidated" ELSE permitState[op]]
    /\ operationState' = [op \in Ops |->
        IF operationState[op] = "authorised" \/ operationState[op] = "permit_issued"
        THEN "denied" ELSE operationState[op]]
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
           requestPayloadDigest, permitTarget, permitArgsDigest, permitPayloadDigest,
           permitEpoch, policyEpoch, grantEpoch, grantUses, readReleased,
           readAuthAtDisclosure, readEpoch, effectCount, effectAuthorizedAtCommit,
           effectTarget, effectArgsDigest, effectPayloadDigest, effectEpoch >>

AdvancePolicyEpoch ==
    /\ policyEpoch = 0
    /\ policyEpoch' = 1
    /\ permitState' = [op \in Ops |-> IF permitState[op] = "issued" THEN "invalidated" ELSE permitState[op]]
    /\ operationState' = [op \in Ops |->
        IF operationState[op] = "authorised" \/ operationState[op] = "permit_issued"
        THEN "denied" ELSE operationState[op]]
    /\ UNCHANGED
        << sessionValid, sessionPrincipal, sessionTenant, sessionTask, sessionAudience,
           claimedPrincipal, opPrincipal, opAction, requestTarget, requestArgsDigest,
           requestPayloadDigest, permitTarget, permitArgsDigest, permitPayloadDigest,
           permitEpoch, grantEpoch, grantRevoked, grantUses, readReleased,
           readAuthAtDisclosure, readEpoch, effectCount, effectAuthorizedAtCommit,
           effectTarget, effectArgsDigest, effectPayloadDigest, effectEpoch >>

Next ==
    \/ \E op \in Ops: Authorize(op)
    \/ \E op \in Ops: IssueCommitPermit(op)
    \/ \E op \in Ops: MutateRequestAfterPermit(op)
    \/ \E op \in Ops: RejectMismatchedCommit(op)
    \/ \E op \in Ops: CommitWrite(op)
    \/ \E op \in Ops: ReleaseRead(op)
    \/ RevokeGrant
    \/ AdvancePolicyEpoch

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ sessionValid \in [Ops -> BOOLEAN]
    /\ sessionPrincipal \in [Ops -> {TrustedPrincipal, AttackerPrincipal}]
    /\ sessionTenant \in [Ops -> {Tenant}]
    /\ sessionTask \in [Ops -> {Task}]
    /\ sessionAudience \in [Ops -> {Audience}]
    /\ claimedPrincipal \in [Ops -> {TrustedPrincipal, AttackerPrincipal}]
    /\ opPrincipal \in [Ops -> ({TrustedPrincipal, AttackerPrincipal} \cup {NoValue})]
    /\ opAction \in [Ops -> ActionNames]
    /\ requestTarget \in [Ops -> ({ExpectedTarget, BadDigest})]
    /\ requestArgsDigest \in [Ops -> ({GoodArgsDigest, BadDigest})]
    /\ requestPayloadDigest \in [Ops -> ({GoodPayloadDigest, BadDigest, NoDigest})]
    /\ operationState \in [Ops -> OperationStates]
    /\ permitState \in [Ops -> PermitStates]
    /\ permitTarget \in [Ops -> ({ExpectedTarget, BadDigest, NoValue})]
    /\ permitArgsDigest \in [Ops -> ({GoodArgsDigest, BadDigest, NoDigest})]
    /\ permitPayloadDigest \in [Ops -> ({GoodPayloadDigest, BadDigest, NoDigest})]
    /\ permitEpoch \in [Ops -> 0..1]
    /\ policyEpoch \in 0..1
    /\ grantEpoch \in 0..1
    /\ grantRevoked \in BOOLEAN
    /\ grantUses \in 0..MaxOperations
    /\ readReleased \in [Ops -> BOOLEAN]
    /\ readAuthAtDisclosure \in [Ops -> BOOLEAN]
    /\ readEpoch \in [Ops -> 0..1]
    /\ effectCount \in [Ops -> 0..1]
    /\ effectAuthorizedAtCommit \in [Ops -> BOOLEAN]
    /\ effectTarget \in [Ops -> ({ExpectedTarget, BadDigest, NoValue})]
    /\ effectArgsDigest \in [Ops -> ({GoodArgsDigest, BadDigest, NoDigest})]
    /\ effectPayloadDigest \in [Ops -> ({GoodPayloadDigest, BadDigest, NoDigest})]
    /\ effectEpoch \in [Ops -> 0..1]

AuthenticatedPrincipalBound ==
    \A op \in Ops:
        operationState[op] \in {"authorised", "permit_issued", "read_released", "committed"}
        => opPrincipal[op] = sessionPrincipal[op]

ReadRequiresAuthorisationBeforeDisclosure ==
    \A op \in Ops: readReleased[op] => readAuthAtDisclosure[op]

EffectRequiresCommitProof ==
    \A op \in Ops:
        effectCount[op] > 0 =>
            /\ effectAuthorizedAtCommit[op]
            /\ permitState[op] = "consumed"
            /\ effectTarget[op] = permitTarget[op]
            /\ effectArgsDigest[op] = permitArgsDigest[op]
            /\ effectPayloadDigest[op] = permitPayloadDigest[op]
            /\ effectEpoch[op] = permitEpoch[op]

SingleUseCommit ==
    \A op \in Ops: effectCount[op] <= 1

QuotaBound ==
    grantUses <= MaxOperations

RevocationInvalidatesOutstandingPermits ==
    grantRevoked => \A op \in Ops: permitState[op] # "issued"

PolicyChangeInvalidatesOutstandingPermits ==
    policyEpoch # grantEpoch => \A op \in Ops: permitState[op] # "issued"

====
