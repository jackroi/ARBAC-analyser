"""ARBAC analyser command line interface.

Checks the reachability of a goal role in an ARBAC system
provided as input.

Usage:
    ./arbac-analyser.py [policy.arbac]

- Pass .arbac file as parameter:
    ./arbac-analyser.py policies/policy1.arbac

- Pass .arbac file content through stdin:
    cat policies/policy1.arbac | ./arbac-analyser.py
"""


import sys
import typing
from typing import List

from .types.arbac import ArbacReachability
from .parser import arbac_parser
from .pruning import pruning_algorithms as pruning
from .reachability import role_reachability as reachability


def main(argv: List[str]):
    """Main: Reads, parses, prunes, and checks role reachability.

    Reads .arbac file content from file or stdin, parses it,
    and if no error occurs, runs an ARBAC pruning algorithm
    (a combination of forward and backward slicing algorithms),
    and then runs the role reachability test.

    Args:
        argv: Argument list:
            argv[0]: program name;
            argv[1]: path to .arbac file (optional).
    """

    # handle cli parameters
    argc = len(argv)

    if argc > 2:
        # too many parameters
        print(f"Too many parameters, usage: {argv[0]} [policy.arbac]", file=sys.stderr)
        sys.exit(1)

    if argc == 1:
        # read from stdin
        text = sys.stdin.read()
    else:
        # read from given file
        filename = argv[1]
        try:
            with open(filename) as f:
                text = f.read()
        except FileNotFoundError:
            # file not found
            print(f"File {filename} not found", file=sys.stderr)
            sys.exit(2)


    # try to parse the input text
    err, res = arbac_parser.parse(text)
    if err:
        # an error occurred while parsing
        # print error message with a contextual help pinpointing the error in the text
        print("Parse error: unexpected token", file=sys.stderr)
        print(res, file=sys.stderr)
        sys.exit(3)

    # the parse result: ArbacReachability instance
    res = typing.cast(ArbacReachability, res)

    print("Input ARBAC\n")
    print(res, "\n")

    # print("Forward sliced ARBAC")
    # print(pruning.forward_slicing(res))

    # print("Backward sliced ARBAC")
    # print(pruning.backward_slicing(res))

    # slice arbac reachability problem
    print("Sliced ARBAC\n")
    sliced_arbac_reachability = pruning.slicing(res)
    print(sliced_arbac_reachability, "\n")

    # verify role reachability
    reachable = reachability.role_reachability(sliced_arbac_reachability)
    print("Reachable" if reachable else "Not reachable")
