---------------- MODULE PACAAuth ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Ops,
    Digests,
    NoDigest,
    Tenants,
    OwnerTenant,
    ToolDigests,
    ExpectedToolDigest,
    TrustedApprovers,
    NoApprover,
    MaxCalls,
    ParentGrants

VARIABLES
    calls,
    tokenState,
    tokenDigest,
    tokenTenant,
    requiresApproval,
    approvalDigest,
    approvalBy,
    issuedToolDigest,
    executionCount,
    childGrants,
    delegated

vars ==
    << calls,
       tokenState,
       tokenDigest,
       tokenTenant,
       requiresApproval,
       approvalDigest,
       approvalBy,
       issuedToolDigest,
       executionCount,
       childGrants,
       delegated >>

TokenStates == {"absent", "issued", "consumed", "expired"}

Init ==
    /\ calls = 0
    /\ tokenState = [op \in Ops |-> "absent"]
    /\ tokenDigest = [op \in Ops |-> NoDigest]
    /\ tokenTenant = [op \in Ops |-> OwnerTenant]
    /\ requiresApproval = [op \in Ops |-> FALSE]
    /\ approvalDigest = [op \in Ops |-> NoDigest]
    /\ approvalBy = [op \in Ops |-> NoApprover]
    /\ issuedToolDigest = [op \in Ops |-> NoDigest]
    /\ executionCount = [op \in Ops |-> 0]
    /\ childGrants = {}
    /\ delegated = FALSE

Authorize(op, digest, dataTenant, approvalRequired, toolDigest) ==
    /\ op \in Ops
    /\ digest \in Digests
    /\ dataTenant \in Tenants
    /\ approvalRequired \in BOOLEAN
    /\ toolDigest \in ToolDigests
    /\ tokenState[op] = "absent"
    /\ calls < MaxCalls
    /\ dataTenant = OwnerTenant
    /\ toolDigest = ExpectedToolDigest
    /\ tokenState' = [tokenState EXCEPT ![op] = "issued"]
    /\ tokenDigest' = [tokenDigest EXCEPT ![op] = digest]
    /\ tokenTenant' = [tokenTenant EXCEPT ![op] = dataTenant]
    /\ requiresApproval' = [requiresApproval EXCEPT ![op] = approvalRequired]
    /\ issuedToolDigest' = [issuedToolDigest EXCEPT ![op] = toolDigest]
    /\ calls' = calls + 1
    /\ UNCHANGED
        << approvalDigest, approvalBy, executionCount, childGrants, delegated >>

Approve(op, digest, approver) ==
    /\ op \in Ops
    /\ digest \in Digests
    /\ approver \in TrustedApprovers
    /\ tokenState[op] = "issued"
    /\ requiresApproval[op]
    /\ tokenDigest[op] = digest
    /\ approvalDigest[op] = NoDigest
    /\ approvalDigest' = [approvalDigest EXCEPT ![op] = digest]
    /\ approvalBy' = [approvalBy EXCEPT ![op] = approver]
    /\ UNCHANGED
        << calls, tokenState, tokenDigest, tokenTenant, requiresApproval,
           issuedToolDigest, executionCount, childGrants, delegated >>

Consume(op, digest, dataTenant) ==
    /\ op \in Ops
    /\ digest \in Digests
    /\ dataTenant \in Tenants
    /\ tokenState[op] = "issued"
    /\ tokenDigest[op] = digest
    /\ tokenTenant[op] = dataTenant
    /\ dataTenant = OwnerTenant
    /\ (~requiresApproval[op] \/ approvalDigest[op] = digest)
    /\ tokenState' = [tokenState EXCEPT ![op] = "consumed"]
    /\ executionCount' = [executionCount EXCEPT ![op] = @ + 1]
    /\ UNCHANGED
        << calls, tokenDigest, tokenTenant, requiresApproval,
           approvalDigest, approvalBy, issuedToolDigest, childGrants, delegated >>

Expire(op) ==
    /\ op \in Ops
    /\ tokenState[op] = "issued"
    /\ tokenState' = [tokenState EXCEPT ![op] = "expired"]
    /\ UNCHANGED
        << calls, tokenDigest, tokenTenant, requiresApproval,
           approvalDigest, approvalBy, issuedToolDigest, executionCount,
           childGrants, delegated >>

Delegate(grants) ==
    /\ ~delegated
    /\ grants \subseteq ParentGrants
    /\ childGrants' = grants
    /\ delegated' = TRUE
    /\ UNCHANGED
        << calls, tokenState, tokenDigest, tokenTenant, requiresApproval,
           approvalDigest, approvalBy, issuedToolDigest, executionCount >>

Next ==
    \/ \E op \in Ops, digest \in Digests, tenant \in Tenants,
          approvalRequired \in BOOLEAN, toolDigest \in ToolDigests:
          Authorize(op, digest, tenant, approvalRequired, toolDigest)
    \/ \E op \in Ops, digest \in Digests, approver \in TrustedApprovers:
          Approve(op, digest, approver)
    \/ \E op \in Ops, digest \in Digests, tenant \in Tenants:
          Consume(op, digest, tenant)
    \/ \E op \in Ops: Expire(op)
    \/ \E grants \in SUBSET ParentGrants: Delegate(grants)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ calls \in Nat
    /\ tokenState \in [Ops -> TokenStates]
    /\ tokenDigest \in [Ops -> (Digests \cup {NoDigest})]
    /\ tokenTenant \in [Ops -> Tenants]
    /\ requiresApproval \in [Ops -> BOOLEAN]
    /\ approvalDigest \in [Ops -> (Digests \cup {NoDigest})]
    /\ approvalBy \in [Ops -> (TrustedApprovers \cup {NoApprover})]
    /\ issuedToolDigest \in [Ops -> (ToolDigests \cup {NoDigest})]
    /\ executionCount \in [Ops -> Nat]
    /\ childGrants \in SUBSET ParentGrants
    /\ delegated \in BOOLEAN

CallBudget ==
    calls <= MaxCalls

SingleUse ==
    \A op \in Ops: executionCount[op] <= 1

ExecutionRequiresConsumedToken ==
    \A op \in Ops:
        executionCount[op] > 0 => tokenState[op] = "consumed"

ExecutionRequiresBoundApproval ==
    \A op \in Ops:
        executionCount[op] > 0 =>
            (~requiresApproval[op] \/ approvalDigest[op] = tokenDigest[op])

TenantIsolation ==
    \A op \in Ops:
        tokenState[op] # "absent" => tokenTenant[op] = OwnerTenant

ApprovalBoundToExactRequest ==
    \A op \in Ops:
        approvalBy[op] # NoApprover =>
            /\ approvalBy[op] \in TrustedApprovers
            /\ approvalDigest[op] = tokenDigest[op]

ToolImplementationPinned ==
    \A op \in Ops:
        tokenState[op] # "absent" =>
            issuedToolDigest[op] = ExpectedToolDigest

DelegationAttenuated ==
    childGrants \subseteq ParentGrants

====
