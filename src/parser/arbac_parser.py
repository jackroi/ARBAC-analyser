"""ARBAC parser: parses ARBAC policies.

The parser uses a lark grammar, defined in the file `arbac.lark` to parse the input text.
This module exports only one function, `parse`.

    Typical usage example:

    err, res = arbac_parser.parse(text)
    if err:
        print("Parse error: unexpected token", file=sys.stderr)
        print(res)
    else:
        print(type(res))    # ArbacReachability
"""


from typing import Union
import lark
from lark import Lark, Transformer
from src.types.arbac import CanAssignRule, CanRevokeRule, UserToRole, UserToRoleAssignment, Arbac, Policy, ArbacReachability


# path of the lark grammar relative to this file
__GRAMMAR = "arbac.lark"


class __TreeToArbacReachability(Transformer):
    """Parse tree to ArbacReachability transformer."""

    # each rule in the grammar has an associated method
    # that is called in a bottom-up manner (depth-first),
    # in order to construct a new ArbacReachability object

    # each method accepts the children as parameter,
    # and returns a new node that will be passed to
    # the parent rule method

    # in any of these method you can assume the children
    # have already been transformed

    def arbac(self, children):
        # construct the ArbacReachability object
        (role_list, user_list, user_to_role_assignment, can_revoke_list, can_assign_list, goal) = children
        policy = Policy(can_assign_list, can_revoke_list)
        arbac = Arbac(role_list, user_list, user_to_role_assignment, policy)
        arbac_reachability = ArbacReachability(arbac, goal)
        return arbac_reachability

    def roles_statement(self, children): return children[0]

    def users_statement(self, children): return children[0]

    def ua_statement(self, children): return UserToRoleAssignment(set(children[0]))

    def cr_statement(self, children): return children[0]

    def ca_statement(self, children): return children[0]

    def goal_statement(self, children): return children[0]

    def role_list(self, children): return list(children)

    def user_list(self, children): return list(children)

    def ua_list(self, children): return list(children)

    def user_role(self, children):
        (user, role) = children
        return UserToRole(user, role)

    def cr_list(self, children): return list(children)

    def cr(self, children):
        (admin_role, target_role) = children
        return CanRevokeRule(admin_role, target_role)

    def ca_list(self, children): return list(children)

    def ca(self, children):
        (admin_role, precondition, target_role) = children
        positive_roles = [ role for (role_type, role) in precondition if role_type == 'pos' ]
        negative_roles = [ role for (role_type, role) in precondition if role_type == 'neg' ]
        return CanAssignRule(admin_role, positive_roles, negative_roles, target_role)

    def precondition(self, children):
        (res,) = children

        if res is None:
            # trivial condition (always true) -> return empty list
            return []
        else:
            # condition list -> return condition list
            return res

    def condition_list(self, children): return list(children)

    def cond_role(self, children): return children[0]

    def trivial_cond(self, children): return None

    def neg_role(self, children): return ('neg', children[0])

    def pos_role(self, children): return ('pos', children[0])

    def role(self, children): return children[0]

    def user(self, children): return children[0]

    def goal(self, children): return children[0]

    def name(self, children): return str(children[0])


# create the parser
__parser = Lark.open(grammar_filename=__GRAMMAR,    # grammar file
                     rel_to=__file__,               # path relative to this file
                     parser="lalr")                 # user lalr parser


def parse(text: str) -> "tuple[bool, Union[ArbacReachability, str]]":
    """Parses a string and constructs the relative ArbacReachability, if string is well formed.

    Args:
        text: The text to parse.

    Returns:
        A tuple (err, res) where:
        - err is a boolean indicating if any parse error occurred
            (True if parse error, False otherwise);
        - res is a pretty diagnostic text to help discover the error
            in the parsed text if an error occurred, otherwise it
            contains the ArbacReachability object result of the parsing.
    """

    # try parse the text
    try:
        # build the parse tree
        tree = __parser.parse(text)
        # return the ArbacReachability object constructed from the parse tree
        return (False, __TreeToArbacReachability().transform(tree))
    except lark.exceptions.UnexpectedInput as e:
        # a parse error occurred
        # return a pretty string pinpointing the error in the text
        return (True, e.get_context(text))
