"""ARBAC related types.

This module exports the following classes:
- `UserToRole`;
- `UserToRoleAssignment`;
- `CanAssignRule`;
- `CanRevokeRule`;
- `Policy`;
- `Arbac`;
- `ArbacReachability`.
"""


from dataclasses import dataclass
from typing import List, FrozenSet


@dataclass(frozen=True)
class UserToRole:
    """Association between a user and a role.

    It is an immutable dataclass (so it has an implicit __hash__ method,
    and can be stored into sets).

    Attributes:
        user: The user name.
        role: The role name.
    """

    user: str
    role: str


@dataclass(frozen=True)
class UserToRoleAssignment:
    """ARBAC user-to-role assignment.

    It is an immutable dataclass (so it has an implicit __hash__ method,
    and can be stored into sets).

    Attributes:
        user_role_list: Immutable set of UserToRole objects.
    """

    user_role_list: FrozenSet[UserToRole]


@dataclass
class CanAssignRule:
    """ARBAC can assign rule.

    Attributes:
        admin_role: The admin role (the one that fires the assignment).
        positive_roles: List of positive roles.
        negative_roles: List of negative roles.
        target_role: The target role (the one that gets assigned
            if preconditions are met).
    """

    admin_role: str
    positive_roles: List[str]
    negative_roles: List[str]
    target_role: str


@dataclass
class CanRevokeRule:
    """ARBAC can revoke rule.

    Attributes:
        admin_role: The admin role (the one that fires the revocation).
        target_role: The target role (the one that gets revocated).
    """

    admin_role: str
    target_role: str


@dataclass
class Policy:
    """ARBAC policy.

    Attributes:
        can_assign: List of can assign rules.
        can_revoke: List of can revoke rules.
    """

    can_assign: List[CanAssignRule]
    can_revoke: List[CanRevokeRule]


@dataclass
class Arbac:
    """ARBAC.

    Attributes:
        role_list: List of roles in the ARBAC system.
        user_list: List of users in the ARBAC system.
        user_to_role_assignment: The user-to-role assignment.
        policy: The policy of the ARBAC system
            (can assign and can revoke rules).
    """

    role_list: List[str]
    user_list: List[str]
    user_to_role_assignment: UserToRoleAssignment
    policy: Policy


@dataclass
class ArbacReachability:
    """ARBAC reachability problem.

    Attributes:
        arbac: The ARBAC system.
        goal: The goal role.
    """

    arbac: Arbac
    goal: str
