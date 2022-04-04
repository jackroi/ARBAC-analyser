"""ARBAC role reachability pruning algoriths"""


from src.types.arbac import CanAssignRule, CanRevokeRule, UserToRole, UserToRoleAssignment, Arbac, Policy, ArbacReachability


def forward_slicing(arbac: Arbac) -> Arbac:
    # TODO: valutare tipo input e output, forse per rendere più simile a backward_slicing meglio ArbacReachability
    """Forward slicing"""

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
            all_contained = len(positive_roles_and_admin.intersection(reachable_roles)) == len(positive_roles_and_admin)

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
        and len(reachable_roles.intersection(rule.positive_roles)) == len(rule.positive_roles)
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
    return Arbac(new_roles, arbac.role_list, arbac.user_to_role_assignment, Policy(new_can_assign, new_can_revoke))


def backward_slicing(arbac: ArbacReachability) -> ArbacReachability:
    """Backward slicing"""

    # start with only the goal role
    relevant_roles = set([ arbac.goal ])

    # enrich the set of relevant roles TODO ...

    return arbac    # TODO: cambiare



def slicing():
    """Forward and Backward slicing combined"""
    pass
