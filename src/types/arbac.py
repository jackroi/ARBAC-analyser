"""ARBAC related types"""


from dataclasses import dataclass
from typing import List


@dataclass
class UserToRole:
    """UserToRole"""

    user: str
    role: str


@dataclass
class UserToRoleAssignment:
    """ARBAC user-to-role assignment"""

    # TODO: eventally other formats, such as dict of list

    user_role_list: List[UserToRole]


@dataclass
class CanAssignRule:
    """ARBAC can assign rule"""

    admin_role: str
    positive_roles: List[str]
    negative_roles: List[str]
    target_role: str


@dataclass
class CanRevokeRule:
    """ARBAC can revoke rule"""
    admin_role: str
    target_role: str


@dataclass
class Policy:
    """ARBAC policy"""

    can_assign: List[CanAssignRule]
    can_revoke: List[CanRevokeRule]


@dataclass
class Arbac:
    """ARBAC"""

    # role list
    role_list: List[str]

    # user list
    user_list: List[str]

    # user to role
    user_to_role_assignment: UserToRoleAssignment

    # policy
    policy: Policy


@dataclass
class ArbacReachability:
    """ARBAC reachability problem"""

    # arbac
    arbac: Arbac

    # goal
    goal: str

