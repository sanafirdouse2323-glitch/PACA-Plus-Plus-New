---------------- MODULE PACAGrant ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Grants, RootGrant, ChildGrant, GrandchildGrant,
    Principals, Tenants, Tasks, Purposes, Actions, Resources, Destinations,
    IntegrityLevels, MaxSensitivity, MaxBudget, MaxTime,
    ChildPrincipal, GrandchildPrincipal, UsePrincipalChild, UsePrincipalGrandchild,
    UseDestination, UseTask, UseSensitivity, UseIntegrity, UseApprovalSatisfied,
    RootPrincipal, RootTenant, RootTaskScope, RootPurposeScope, RootActions, RootResources,
    RootDestinations, RootDelegatees, RootMaxSensitivity, RootIntegrityLevels,
    RootRequiresApproval, RootNotBefore, RootExpiry, RootBudget,
    NoGrant, NoPrincipal, NoTenant, NoTask

VARIABLES
    grantState, grantParent, grantSubject, grantTenant, grantTaskScope, grantPurposeScope,
    grantActions, grantResources, grantDestinations, grantDelegatees, grantMaxSensitivity,
    grantIntegrityLevels, grantRequiresApproval, grantNotBefore, grantExpiry,
    grantAllocation, grantRemaining, grantSpent, grantUseCount, now

vars ==
    << grantState, grantParent, grantSubject, grantTenant, grantTaskScope, grantPurposeScope,
       grantActions, grantResources, grantDestinations, grantDelegatees, grantMaxSensitivity,
       grantIntegrityLevels, grantRequiresApproval, grantNotBefore, grantExpiry,
       grantAllocation, grantRemaining, grantSpent, grantUseCount, now >>

GrantStates == {"absent", "active", "revoked", "expired"}

RECURSIVE DescendsFrom(_, _), GrantChainActive(_)
DescendsFrom(candidate, ancestor) ==
    IF candidate \notin Grants THEN FALSE
    ELSE
        grantParent[candidate] = ancestor
        \/ (grantParent[candidate] # NoGrant
            /\ DescendsFrom(grantParent[candidate], ancestor))

GrantChainActive(g) ==
    IF g \notin Grants THEN FALSE
    ELSE
        /\ grantState[g] = "active"
        /\ now >= grantNotBefore[g]
        /\ now < grantExpiry[g]
        /\ (grantParent[g] = NoGrant \/ GrantChainActive(grantParent[g]))

Init ==
    /\ grantState = [g \in Grants |-> IF g = RootGrant THEN "active" ELSE "absent"]
    /\ grantParent = [g \in Grants |-> NoGrant]
    /\ grantSubject = [g \in Grants |-> IF g = RootGrant THEN RootPrincipal ELSE NoPrincipal]
    /\ grantTenant = [g \in Grants |-> IF g = RootGrant THEN RootTenant ELSE NoTenant]
    /\ grantTaskScope = [g \in Grants |-> IF g = RootGrant THEN RootTaskScope ELSE {}]
    /\ grantPurposeScope = [g \in Grants |-> IF g = RootGrant THEN RootPurposeScope ELSE {}]
    /\ grantActions = [g \in Grants |-> IF g = RootGrant THEN RootActions ELSE {}]
    /\ grantResources = [g \in Grants |-> IF g = RootGrant THEN RootResources ELSE {}]
    /\ grantDestinations = [g \in Grants |-> IF g = RootGrant THEN RootDestinations ELSE {}]
    /\ grantDelegatees = [g \in Grants |-> IF g = RootGrant THEN RootDelegatees ELSE {}]
    /\ grantMaxSensitivity = [g \in Grants |-> IF g = RootGrant THEN RootMaxSensitivity ELSE 0]
    /\ grantIntegrityLevels = [g \in Grants |-> IF g = RootGrant THEN RootIntegrityLevels ELSE {}]
    /\ grantRequiresApproval = [g \in Grants |-> IF g = RootGrant THEN RootRequiresApproval ELSE TRUE]
    /\ grantNotBefore = [g \in Grants |-> IF g = RootGrant THEN RootNotBefore ELSE 0]
    /\ grantExpiry = [g \in Grants |-> IF g = RootGrant THEN RootExpiry ELSE 0]
    /\ grantAllocation = [g \in Grants |-> IF g = RootGrant THEN RootBudget ELSE 0]
    /\ grantRemaining = [g \in Grants |-> IF g = RootGrant THEN RootBudget ELSE 0]
    /\ grantSpent = [g \in Grants |-> 0]
    /\ grantUseCount = [g \in Grants |-> 0]
    /\ now = 0

Delegate(child, parent, recipient, task, actions, resources, purposes, destinations,
         delegatees, maxSensitivity, integrityLevels, requiresApproval, expiry, budget) ==
    /\ child \in Grants
    /\ parent \in Grants
    /\ child # parent
    /\ grantState[child] = "absent"
    /\ GrantChainActive(parent)
    /\ recipient \in grantDelegatees[parent]
    /\ task \in grantTaskScope[parent]
    /\ actions \subseteq grantActions[parent]
    /\ resources \subseteq grantResources[parent]
    /\ purposes \subseteq grantPurposeScope[parent]
    /\ destinations \subseteq grantDestinations[parent]
    /\ delegatees \subseteq grantDelegatees[parent]
    /\ maxSensitivity <= grantMaxSensitivity[parent]
    /\ integrityLevels \subseteq grantIntegrityLevels[parent]
    /\ (~grantRequiresApproval[parent] \/ requiresApproval)
    /\ expiry <= grantExpiry[parent]
    /\ expiry > now
    /\ budget \in 1..grantRemaining[parent]
    /\ grantState' = [grantState EXCEPT ![child] = "active"]
    /\ grantParent' = [grantParent EXCEPT ![child] = parent]
    /\ grantSubject' = [grantSubject EXCEPT ![child] = recipient]
    /\ grantTenant' = [grantTenant EXCEPT ![child] = grantTenant[parent]]
    /\ grantTaskScope' = [grantTaskScope EXCEPT ![child] = {task}]
    /\ grantPurposeScope' = [grantPurposeScope EXCEPT ![child] = purposes]
    /\ grantActions' = [grantActions EXCEPT ![child] = actions]
    /\ grantResources' = [grantResources EXCEPT ![child] = resources]
    /\ grantDestinations' = [grantDestinations EXCEPT ![child] = destinations]
    /\ grantDelegatees' = [grantDelegatees EXCEPT ![child] = delegatees]
    /\ grantMaxSensitivity' = [grantMaxSensitivity EXCEPT ![child] = maxSensitivity]
    /\ grantIntegrityLevels' = [grantIntegrityLevels EXCEPT ![child] = integrityLevels]
    /\ grantRequiresApproval' = [grantRequiresApproval EXCEPT ![child] = requiresApproval]
    /\ grantNotBefore' = [grantNotBefore EXCEPT ![child] = now]
    /\ grantExpiry' = [grantExpiry EXCEPT ![child] = expiry]
    /\ grantAllocation' = [grantAllocation EXCEPT ![child] = budget]
    /\ grantRemaining' = [grantRemaining EXCEPT ![parent] = @ - budget, ![child] = budget]
    /\ grantSpent' = [grantSpent EXCEPT ![child] = 0]
    /\ grantUseCount' = [grantUseCount EXCEPT ![child] = 0]
    /\ UNCHANGED now

UseGrant(g, principal) ==
    /\ g \in Grants
    /\ principal = grantSubject[g]
    /\ GrantChainActive(g)
    /\ UseAction \in grantActions[g]
    /\ UseResource \in grantResources[g]
    /\ UsePurpose \in grantPurposeScope[g]
    /\ UseDestination \in grantDestinations[g]
    /\ UseTask \in grantTaskScope[g]
    /\ UseSensitivity <= grantMaxSensitivity[g]
    /\ UseIntegrity \in grantIntegrityLevels[g]
    /\ (grantRequiresApproval[g] => UseApprovalSatisfied)
    /\ grantRemaining[g] > 0
    /\ grantRemaining' = [grantRemaining EXCEPT ![g] = @ - 1]
    /\ grantSpent' = [grantSpent EXCEPT ![g] = @ + 1]
    /\ grantUseCount' = [grantUseCount EXCEPT ![g] = @ + 1]
    /\ UNCHANGED
        << grantState, grantParent, grantSubject, grantTenant, grantTaskScope, grantPurposeScope,
           grantActions, grantResources, grantDestinations, grantDelegatees, grantMaxSensitivity,
           grantIntegrityLevels, grantRequiresApproval, grantNotBefore, grantExpiry,
           grantAllocation, now >>

DelegateToChild ==
    Delegate(ChildGrant, RootGrant, ChildPrincipal, UseTask, {UseAction}, {UseResource},
             {UsePurpose}, {UseDestination}, {GrandchildPrincipal}, 2, {"trusted"}, TRUE, 2, 2)

DelegateToGrandchild ==
    Delegate(GrandchildGrant, ChildGrant, GrandchildPrincipal, UseTask, {UseAction},
             {UseResource}, {UsePurpose}, {UseDestination}, {}, 1, {"trusted"}, TRUE, 1, 1)
RevokeGrant(g) ==
    /\ g \in Grants
    /\ grantState[g] = "active"
    /\ grantState' = [candidate \in Grants |->
        IF candidate = g \/ DescendsFrom(candidate, g)
        THEN "revoked" ELSE grantState[candidate]]
    /\ UNCHANGED
        << grantParent, grantSubject, grantTenant, grantTaskScope, grantPurposeScope,
           grantActions, grantResources, grantDestinations, grantDelegatees, grantMaxSensitivity,
           grantIntegrityLevels, grantRequiresApproval, grantNotBefore, grantExpiry,
           grantAllocation, grantRemaining, grantSpent, grantUseCount, now >>

ExpireGrant(g) ==
    /\ g \in Grants
    /\ grantState[g] = "active"
    /\ now >= grantExpiry[g]
    /\ grantState' = [candidate \in Grants |->
        IF candidate = g \/ (DescendsFrom(candidate, g) /\ grantState[candidate] = "active")
        THEN "expired" ELSE grantState[candidate]]
    /\ UNCHANGED
        << grantParent, grantSubject, grantTenant, grantTaskScope, grantPurposeScope,
           grantActions, grantResources, grantDestinations, grantDelegatees, grantMaxSensitivity,
           grantIntegrityLevels, grantRequiresApproval, grantNotBefore, grantExpiry,
           grantAllocation, grantRemaining, grantSpent, grantUseCount, now >>

AdvanceTime ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED
        << grantState, grantParent, grantSubject, grantTenant, grantTaskScope, grantPurposeScope,
           grantActions, grantResources, grantDestinations, grantDelegatees, grantMaxSensitivity,
           grantIntegrityLevels, grantRequiresApproval, grantNotBefore, grantExpiry,
           grantAllocation, grantRemaining, grantSpent, grantUseCount >>

Next ==
    \/ DelegateToChild
    \/ DelegateToGrandchild
    \/ UseGrant(ChildGrant, UsePrincipalChild)
    \/ UseGrant(GrandchildGrant, UsePrincipalGrandchild)
    \/ \E g \in Grants: RevokeGrant(g)
    \/ \E g \in Grants: ExpireGrant(g)
    \/ AdvanceTime
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ grantState \in [Grants -> GrantStates]
    /\ grantParent \in [Grants -> (Grants \cup {NoGrant})]
    /\ grantSubject \in [Grants -> (Principals \cup {NoPrincipal})]
    /\ grantTenant \in [Grants -> (Tenants \cup {NoTenant})]
    /\ grantTaskScope \in [Grants -> SUBSET Tasks]
    /\ grantPurposeScope \in [Grants -> SUBSET Purposes]
    /\ grantActions \in [Grants -> SUBSET Actions]
    /\ grantResources \in [Grants -> SUBSET Resources]
    /\ grantDestinations \in [Grants -> SUBSET Destinations]
    /\ grantDelegatees \in [Grants -> SUBSET Principals]
    /\ grantMaxSensitivity \in [Grants -> 0..MaxSensitivity]
    /\ grantIntegrityLevels \in [Grants -> SUBSET IntegrityLevels]
    /\ grantRequiresApproval \in [Grants -> BOOLEAN]
    /\ grantNotBefore \in [Grants -> 0..MaxTime]
    /\ grantExpiry \in [Grants -> 0..MaxTime]
    /\ grantAllocation \in [Grants -> 0..MaxBudget]
    /\ grantRemaining \in [Grants -> 0..MaxBudget]
    /\ grantSpent \in [Grants -> 0..MaxBudget]
    /\ grantUseCount \in [Grants -> 0..MaxBudget]
    /\ now \in 0..MaxTime

DelegationAttenuated ==
    \A child \in Grants:
        grantParent[child] # NoGrant =>
            LET parent == grantParent[child] IN
                /\ grantTenant[child] = grantTenant[parent]
                /\ grantTaskScope[child] \subseteq grantTaskScope[parent]
                /\ grantPurposeScope[child] \subseteq grantPurposeScope[parent]
                /\ grantActions[child] \subseteq grantActions[parent]
                /\ grantResources[child] \subseteq grantResources[parent]
                /\ grantDestinations[child] \subseteq grantDestinations[parent]
                /\ grantDelegatees[child] \subseteq grantDelegatees[parent]
                /\ grantMaxSensitivity[child] <= grantMaxSensitivity[parent]
                /\ grantIntegrityLevels[child] \subseteq grantIntegrityLevels[parent]
                /\ (~grantRequiresApproval[parent] \/ grantRequiresApproval[child])
                /\ grantNotBefore[child] >= grantNotBefore[parent]
                /\ grantExpiry[child] <= grantExpiry[parent]

BudgetWithinAllocation ==
    \A g \in Grants:
        /\ grantRemaining[g] + grantSpent[g] <= grantAllocation[g]
        /\ grantUseCount[g] = grantSpent[g]

RevocationIsTransitive ==
    \A parent \in Grants:
        grantState[parent] = "revoked" =>
            \A child \in Grants: DescendsFrom(child, parent) => grantState[child] = "revoked"

====
