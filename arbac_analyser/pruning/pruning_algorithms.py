"""ARBAC role reachability pruning algoriths.

Pruning algoriths are used to simplify the ARBAC system,
in order to reduce the role reachability problem to a
smaller, and hopefully tractable, state space.

This module exports 3 functions:
- `forward_slicing`;
- `backward_slicing`;
- `slicing`.

    Typical usage example:

    arbac_reachability = ArbacReachability(...)

    arbac_reachability_1 = forward_slicing(arbac_reachability)
    arbac_reachability_2 = backward_slicing(arbac_reachability)
    arbac_reachability_3 = slicing(arbac_reachability)
"""


from arbac_analyser.types.arbac import UserToRoleAssignment, Arbac, Policy, ArbacReachability


def forward_slicing(arbac_reachability: ArbacReachability) -> ArbacReachability:
    """Prunes the ArbacReachability using the forward slicing algorithm.

    Computes an over-approximation of the reachable roles,
    and then simplify the ARBAC system according to it,
    in a way to preserve the solution to the role reachability
    problem.

    Args:
        arbac_reachability: The ARBAC reachability problem instance to prune.

    Returns:
        A new pruned ArbacReachability object.
    """

    arbac = arbac_reachability.arbac

    # set of reachable roles (that will be incrementally enriched
    # until a fixed point is reached)
    reachable_roles = set()

    # roles assigned in the first user to role assignment are reachable
    for user_to_role in arbac.user_to_role_assignment.user_role_list:
        reachable_roles.add(user_to_role.role)

    # enrich the set with other possibly reachable roles
    prev_len = 0
    curr_len = len(reachable_roles)
    # repeat until the reachable roles set stops increasing
    while curr_len != prev_len:
        # set of newly reachable roles
        new_reachable_roles = set()

        # for each can assign rule in the policy
        # if both can assign admin role and all positive roles are contained
        # in the previous set of reachable roles
        # add the can assign target role to the new_reachable_roles set
        for can_assign in arbac.policy.can_assign:
            # build set of positive roles and admin role
            target_role = can_assign.target_role
            positive_roles_and_admin = set(can_assign.positive_roles)
            positive_roles_and_admin.add(can_assign.admin_role)

            # check if all these roles are contained in the current set of reachable roles
            all_contained = positive_roles_and_admin.issubset(reachable_roles)

            # if all contained, the target role of the can assign might be reachable
            # so it gets added to the new reachable roles set
            if all_contained:
                new_reachable_roles.add(target_role)

        # add the new reachable roles to the set of all the reachable roles
        reachable_roles.update(new_reachable_roles)
        # update set length
        prev_len = curr_len
        curr_len = len(reachable_roles)

    # keep only interesting can assign rules
    valid_can_assign = lambda rule: (
        rule.admin_role in reachable_roles
        and rule.target_role in reachable_roles
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
        new_can_assign[i].negative_roles = list(
            reachable_roles.intersection(new_can_assign[i].negative_roles)
        )

    # keep only interesting (reachable) roles
    new_roles = list(reachable_roles)

    # build the new pruned ARBAC
    new_arbac = Arbac(new_roles,
                      arbac.user_list,
                      arbac.user_to_role_assignment,
                      Policy(new_can_assign, new_can_revoke))
    return ArbacReachability(new_arbac, arbac_reachability.goal)


def backward_slicing(arbac_reachability: ArbacReachability) -> ArbacReachability:
    """Prunes the ArbacReachability using the backward slicing algorithm.

    Computes an over-approximation of the relevant roles to assign
    the goal, and then simplify the ARBAC system according to it,
    in a way to preserve the solution to the role reachability
    problem.

    Args:
        arbac_reachability: The ARBAC reachability problem instance to prune.

    Returns:
        A new pruned ArbacReachability object.
    """

    # set of relevant roles (which starts with only the goal role
    # and that will be incrementally enriched until a fixed point
    # is reached)
    relevant_roles = set([ arbac_reachability.goal ])

    # enrich the set of relevant roles with all the roles
    # mentioned in the can assign rules, whose target role
    # is contained in the current set of relevant roles
    prev_len = 0;
    curr_len = len(relevant_roles)
    # repeat until the relevant roles set stops increasing
    while curr_len != prev_len:
        # list of newly relevant roles
        new_relevant_roles = []

        # for each can assign rule in the policy
        # if the target role is contained in the
        # previous set of relevant roles,
        # add all the other mentioned roles
        # (positives, negatives, and admin role)
        # to the new_relevant_roles list
        for rule in arbac_reachability.arbac.policy.can_assign:
            if rule.target_role in relevant_roles:
                new_relevant_roles.extend(rule.positive_roles
                                          + rule.negative_roles
                                          + [ rule.admin_role ])

        # add the new relevant roles to the set of all the relevant roles
        relevant_roles.update(new_relevant_roles)
        # update set length
        prev_len = curr_len
        curr_len = len(relevant_roles)

    # keep only interesting can assign rules,
    # only those that assign a role inside relevant_roles
    valid_can_assign = lambda rule: rule.target_role in relevant_roles
    new_can_assign = list(filter(valid_can_assign,
                                 arbac_reachability.arbac.policy.can_assign))

    # keep only interesting can revoke rules
    # only those that revoke a role inside relevant_roles
    valid_can_revoke = lambda rule: rule.target_role in relevant_roles
    new_can_revoke = list(filter(valid_can_revoke,
                                 arbac_reachability.arbac.policy.can_revoke))

    # keep only interesting (relevant) roles
    new_roles = list(relevant_roles)

    # update user-to-role assignment
    # keep only user-to-role with valid roles (roles not removed in the previous step)
    valid_user_to_role = lambda user_to_role: user_to_role.role in new_roles
    new_user_to_role_assignment = set(
        filter(valid_user_to_role,
               arbac_reachability.arbac.user_to_role_assignment.user_role_list)
    )

    # build the new pruned ARBAC
    arbac = Arbac(new_roles,
                  arbac_reachability.arbac.user_list,
                  UserToRoleAssignment(new_user_to_role_assignment),
                  Policy(new_can_assign, new_can_revoke))
    return ArbacReachability(arbac, arbac_reachability.goal)


def slicing(arbac_reachability: ArbacReachability) -> ArbacReachability:
    """Prunes the ArbacReachability using a forward and backward slicing algorithms.

    Applies repetitively the forward slicing algorithm, followed
    by the backward slicing algorithm, until the ARBAC system
    stabilises to a fixed point.

    Args:
        arbac_reachability: The ARBAC reachability problem instance to prune.

    Returns:
        A new pruned ArbacReachability object.
    """

    # prune the ARBAC system until a fixed point is reached
    pruned_arbac_reachability = arbac_reachability
    changed = True
    while changed:
        # apply forward slicing
        new_pruned_arbac_reachability = forward_slicing(pruned_arbac_reachability)
        # apply backward slicing
        new_pruned_arbac_reachability = backward_slicing(new_pruned_arbac_reachability)

        # check if ARBAC changed
        changed = pruned_arbac_reachability != new_pruned_arbac_reachability
        # store the new pruend system
        pruned_arbac_reachability = new_pruned_arbac_reachability

    return pruned_arbac_reachability
