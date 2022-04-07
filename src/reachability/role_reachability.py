"""ARBAC role reachability."""


from typing import List
from src.types.arbac import Arbac, Policy, ArbacReachability, UserToRoleAssignment, CanAssignRule, CanRevokeRule, UserToRole


def role_reachability(arbac_reachability: ArbacReachability ) -> bool:
    """Solves the given ARBAC role reachability problem.

    Generates all the possible user-to-role assignment, checking if
    one of them contains a user with the goal role.

    Args:
        arbac_reachability: The ARBAC role reachability problem.

    Returns:
        A boolean indicating whether the goal role is reachable
        from the initial user-to-role assignment, using the given
        policy.
    """

    # queue of the user-to-role assignments that have still to be processed
    to_process_queue: List[UserToRoleAssignment] = []
    # list of the user-to-role assignments already processed
    visited: List[UserToRoleAssignment] = []

    # add initial user-to-role assignment to the queue
    to_process_queue.append(arbac_reachability.arbac.user_to_role_assignment)

    # while queue is not empty
    while to_process_queue:
        # extract an user-to-role assignment from the queue
        user_to_role_assignment = to_process_queue.pop(0)

        # if already visited, analyse the next in the queue
        if user_to_role_assignment in visited:
            continue

        # mark the user-to-role assignment as visited, by inserting it into the visited list
        visited.append(user_to_role_assignment)

        # check if any user has the goal role
        goal_reached = any(user_role.role == arbac_reachability.goal
                           for user_role in user_to_role_assignment.user_role_list)

        # if goal reached, just return True
        if goal_reached:
            return True

        # generate all the possible new user-to-role assignments reachable from the current
        # user-to-role assignment, using a single rule (can assign or can revoke) from the policy
        # for all the user in the system

        # for each can assign rule
        for can_assign_rule in arbac_reachability.arbac.policy.can_assign:
            # for each user
            for user in arbac_reachability.arbac.user_list:
                # try to execute the assignment and add the new user-to-role assignment to the queue
                new_user_to_role_assignment = assign(user_to_role_assignment, can_assign_rule, user)
                # add it to the queue only if it is different from the parent one
                if user_to_role_assignment != new_user_to_role_assignment:
                    to_process_queue.append(new_user_to_role_assignment)

        # for each can revoke rule
        for can_revoke_rule in arbac_reachability.arbac.policy.can_revoke:
            # for each user
            for user in arbac_reachability.arbac.user_list:
                # try to execute the revocation and add the new user-to-role assignment to the queue
                new_user_to_role_assignment = revoke(user_to_role_assignment, can_revoke_rule, user)
                # add it to the queue only if it is different from the parent one
                if user_to_role_assignment != new_user_to_role_assignment:
                    to_process_queue.append(new_user_to_role_assignment)

    return False


def assign(user_to_role_assignment: UserToRoleAssignment, can_assign_rule: CanAssignRule, target_user: str):
    """Tries to apply the can assign rule to the target_user.

    Condition to apply the can assign rule:
    - a user with role can_assign_rule.admin_role is present in the user_to_role_assignment
    - the target_user has all the can_assign_rule.positive_roles
    - the target_user doesn't have any can_assign_rule.negative_roles
    - the target_user doesn't already have the can_assign_rule.target_role

    Args:
        user_to_role_assignment: The starting user-to-role assignment.
        can_assign_rule: The can assign rule to apply.
        target_user: The target user.

    Returns:
        A new UserToRoleAssignment if all the can assign preconditions are met,
        the input user_to_role_assignment otherwise.
    """

    # check if there is any user with the required admin role for firing the can_assign_rule
    admin_present = any(user_role.role == can_assign_rule.admin_role
                        for user_role in user_to_role_assignment.user_role_list)

    # list of roles of the target user
    target_user_roles = [ user_role.role
                          for user_role in user_to_role_assignment.user_role_list
                          if user_role.user == target_user ]

    # check if the target_user has all the positive roles
    positive_roles_present = all(pos_role in target_user_roles
                                 for pos_role in can_assign_rule.positive_roles)

    # check if the target_user has any negative roles
    negative_roles_present = any(neg_role in target_user_roles
                                 for neg_role in can_assign_rule.negative_roles)

    # check if the target user has already the target role
    already_have_role = can_assign_rule.target_role in target_user_roles

    if (admin_present
        and positive_roles_present
        and not negative_roles_present
        and not already_have_role):

        # all conditions met: build and return the new user-to-role assignment
        new_user_role_list = user_to_role_assignment.user_role_list.copy()
        new_user_role_list.add(UserToRole(target_user, can_assign_rule.target_role))
        return UserToRoleAssignment(new_user_role_list)
    else:
        # some conditions not met: return the old user-to-role assignment
        return user_to_role_assignment


def revoke(user_to_role_assignment: UserToRoleAssignment, can_revoke_rule: CanRevokeRule, target_user: str):
    """Tries to apply the can revoke rule to the target_user.

    Condition to apply the can revoke rule:
    - a user with role can_revoke_rule.admin_role is present in the user_to_role_assignment
    - the target_user has the can_revoke_rule.target_role

    Args:
        user_to_role_assignment: The starting user-to-role assignment.
        can_revoke_rule: The can revoke rule to apply.
        target_user: The target user.

    Returns:
        A new UserToRoleAssignment if all the can revoke preconditions are met,
        the input user_to_role_assignment otherwise.
    """

    # check if there is any user with the required admin role for firing the can_revoke_rule
    admin_present = any(user_role.role == can_revoke_rule.admin_role
                        for user_role in user_to_role_assignment.user_role_list)

    if admin_present:
        # all conditions met: build and return the new user-to-role assignment
        # TODO: fix type error (probably auto-fixes when fixing imports)
        new_user_role_list = set(filter(
            lambda user_role: user_role.user != target_user or user_role.role != can_revoke_rule.target_role,
            user_to_role_assignment.user_role_list
        ))
        return UserToRoleAssignment(new_user_role_list)
    else:
        # some conditions not met: return the old user-to-role assignment
        return user_to_role_assignment
