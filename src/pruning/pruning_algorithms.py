"""ARBAC role reachability pruning algoriths"""


from src.types.arbac import UserToRoleAssignment, Arbac, Policy, ArbacReachability


def forward_slicing(arbac_reachability: ArbacReachability) -> ArbacReachability:
    # TODO: valutare tipo input e output, forse per rendere più simile a backward_slicing meglio ArbacReachability
    """Forward slicing"""

    arbac = arbac_reachability.arbac

    reachable_roles = set()

    # roles assigned in the first user to role assignment
    for user_to_role in arbac.user_to_role_assignment.user_role_list:
        reachable_roles.add(user_to_role.role)

    # enrich the set with other possibly reachable roles
    prev_len = 0
    curr_len = len(reachable_roles)
    while curr_len != prev_len:
        new_reachable_roles = set()
        for can_assign in arbac.policy.can_assign:
            target_role = can_assign.target_role
            positive_roles_and_admin = set(can_assign.positive_roles)
            positive_roles_and_admin.add(can_assign.admin_role)

            # if length of intersection of positive_roles_and_admin and reachable_roles
            # is equal to length of positive_roles_and_admin, then positive_roles_and_admin
            # is a subset of reachable_roles
            all_contained = positive_roles_and_admin.issubset(reachable_roles)
            #all_contained_old = len(positive_roles_and_admin.intersection(reachable_roles)) == len(positive_roles_and_admin)

            if all_contained:
                new_reachable_roles.add(target_role)

        reachable_roles.update(new_reachable_roles)
        prev_len = curr_len
        curr_len = len(reachable_roles)

    # keep only interesting can assign rules
    #new_can_assign = []
    #for rule in arbac.policy.can_assign:
    #    if (rule.admin_role in reachable_roles
    #        and rule.target_role in reachable_roles
    #        and len(reachable_roles.intersection(rule.positive_roles)) == len(rule.positive_roles)):

    #        new_can_assign.append(rule)

    valid_can_assign = lambda rule: (
        rule.admin_role in reachable_roles
        and rule.target_role in reachable_roles
        #and len(reachable_roles.intersection(rule.positive_roles)) == len(rule.positive_roles)
        and reachable_roles.issuperset(rule.positive_roles)
    )
    new_can_assign = list(filter(valid_can_assign, arbac.policy.can_assign))

    # keep only interesting can revoke rules
    valid_can_revoke = lambda rule: (
        rule.admin_role in reachable_roles
        and rule.target_role in reachable_roles
    )
    new_can_revoke = list(filter(valid_can_revoke, arbac.policy.can_revoke))

    # remove any non-reachable can assign negative role
    for i in range(len(new_can_assign)):
        new_can_assign[i].negative_roles = list(reachable_roles.intersection(new_can_assign[i].negative_roles))

    # keep only interesting (reachable) roles
    new_roles = list(reachable_roles)

    # build the new pruned arbac
    new_arbac = Arbac(new_roles, arbac.user_list, arbac.user_to_role_assignment, Policy(new_can_assign, new_can_revoke))
    return ArbacReachability(new_arbac, arbac_reachability.goal)


def backward_slicing(arbac_reachability: ArbacReachability) -> ArbacReachability:
    """Backward slicing"""

    # start with only the goal role
    relevant_roles = set([ arbac_reachability.goal ])

    # enrich the set of relevant roles TODO ...
    prev_len = 0;
    curr_len = len(relevant_roles)
    while curr_len != prev_len:
        new_relevant_roles = []
        for rule in arbac_reachability.arbac.policy.can_assign:
            if rule.target_role in relevant_roles:
                new_relevant_roles.extend(rule.positive_roles + rule.negative_roles + [ rule.admin_role ])

        relevant_roles.update(new_relevant_roles)
        prev_len = curr_len
        curr_len = len(relevant_roles)

    # TODO: controllare algoritmo per assicurarsi che siano davvero questi i casi in cui rimuovere rules

    # keep only interesting can assign rules,
    # only those that assign a role inside relevant_roles
    valid_can_assign = lambda rule: rule.target_role in relevant_roles
    new_can_assign = list(filter(valid_can_assign, arbac_reachability.arbac.policy.can_assign))

    # keep only interesting can revoke rules
    # only those that revoke a role inside relevant_roles
    valid_can_revoke = lambda rule: rule.target_role in relevant_roles
    new_can_revoke = list(filter(valid_can_revoke, arbac_reachability.arbac.policy.can_revoke))

    # keep only interesting (relevant) roles
    new_roles = list(relevant_roles)

    # update user to role assignment
    # TODO: this step is not present in the slides algoriths, but should be needed to keep user_to_role_assignment consistent
    valid_user_to_role = lambda user_to_role: user_to_role.role in new_roles
    new_user_to_role_assignment = list(filter(valid_user_to_role, arbac_reachability.arbac.user_to_role_assignment.user_role_list))

    # build the new pruned arbac
    arbac = Arbac(new_roles,
                  arbac_reachability.arbac.user_list,
                  UserToRoleAssignment(new_user_to_role_assignment),
                  Policy(new_can_assign, new_can_revoke))
    return ArbacReachability(arbac, arbac_reachability.goal)



def slicing(arbac_reachability: ArbacReachability) -> ArbacReachability:
    """Forward and Backward slicing combined"""

    pruned_arbac_reachability = arbac_reachability
    changed = True
    while changed:
        new_pruned_arbac_reachability = forward_slicing(pruned_arbac_reachability)
        new_pruned_arbac_reachability = backward_slicing(new_pruned_arbac_reachability)
        changed = pruned_arbac_reachability != new_pruned_arbac_reachability    # TODO: capire se funziona
        pruned_arbac_reachability = new_pruned_arbac_reachability

    return pruned_arbac_reachability   # TODO

