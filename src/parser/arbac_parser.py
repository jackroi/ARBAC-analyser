"""ARBAC parser: parses arbac policies.

TODO: describe more
"""


from typing import Union
import lark
from lark import Lark, Transformer
#import .arbac  # TODO maybe ?????
from src.types.arbac import CanAssignRule, CanRevokeRule, UserToRole, UserToRoleAssignment, Arbac, Policy, ArbacReachability


GRAMMAR = "arbac.lark"


class TreeToArbacReachability(Transformer):

    def spec(self, t):
        (role_list, user_list, user_to_role_assignment, can_revoke_list, can_assign_list, goal) = t
        policy = Policy(can_assign_list, can_revoke_list)
        arbac = Arbac(role_list, user_list, user_to_role_assignment, policy)
        arbac_reachability = ArbacReachability(arbac, goal)
        return arbac_reachability

    def roles_statement(self, t):
        (res,) = t
        return res

    def users_statement(self, t):
        (res,) = t
        return res

    def ua_statement(self, t):
        (res,) = t
        return UserToRoleAssignment(res)

    def cr_statement(self, t):
        (res,) = t
        return res

    def ca_statement(self, t):
        (res,) = t
        return res

    def goal_statement(self, t):
        return TreeToArbacReachability._get_str(t)

    def role_list(self, t):
        return list(t)

    def user_list(self, t):
        return list(t)

    def ua_list(self, t):
        return list(t)

    def user_role(self, t):
        (user, role) = t
        return UserToRole(user, role)

    def cr_list(self, t):
        return list(t)

    def cr(self, t):
        (admin_role, target_role) = t
        return CanRevokeRule(admin_role, target_role)

    def ca_list(self, t):
        return list(t)

    def ca(self, t):
        (admin_role, precondition, target_role) = t

        positive_roles = [ role for (role_type, role) in precondition if role_type == 'pos' ]
        negative_roles = [ role for (role_type, role) in precondition if role_type == 'neg' ]

        return CanAssignRule(admin_role, positive_roles, negative_roles, target_role)

    def precondition(self, t):
        (res,) = t

        if res is None:
            # trivial condition (always true) -> return empty list
            return []
        else:
            # condition list -> return condition list
            return res


    def condition_list(self, t):
        return list(t)

    def cond_role(self, t):
        (res,) = t
        return res

    def trivial_cond(self, t):
        return None

    def neg_role(self, t):
        return ('neg', TreeToArbacReachability._get_str(t))
        #return TreeToArbacReachability._get_str(t)

    def pos_role(self, t):
        return ('pos', TreeToArbacReachability._get_str(t))
        #return TreeToArbacReachability._get_str(t)

    def role(self, t): return TreeToArbacReachability._get_str(t)

    def user(self, t): return TreeToArbacReachability._get_str(t)

    def goal(self, t): return TreeToArbacReachability._get_str(t)

    def name(self, t): return TreeToArbacReachability._get_str(t)

    @staticmethod
    def _get_str(tokens):
        # get first token
        (s,) = tokens
        return str(s)




parser = Lark.open(grammar_filename=GRAMMAR,
                   rel_to=__file__,
                   parser="lalr")
                   #transformer=TreeToArbacReachability())




def parse(text: str) -> "tuple[bool, Union[ArbacReachability, str]]":
    try:
        tree = parser.parse(text)
        return (False, TreeToArbacReachability().transform(tree))
    except lark.exceptions.UnexpectedInput as e:
        return (True, e.get_context(text))

