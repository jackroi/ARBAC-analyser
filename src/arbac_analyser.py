#!/usr/bin/env python3

"""ARBAC analyser: role reachability verifier.

TODO: describe how to use this from cli
"""


import sys
import typing
from typing import List
from src.types.arbac import ArbacReachability
from src.parser import arbac_parser
from src.pruning import pruning_algorithms as pruning


def main(argv: List[str]):
    """Main"""

    argc = len(argv)

    if argc > 2:
        print(f"Too many parameters, usage: {argv[0]} [policy.arbac]", file=sys.stderr)
        sys.exit(1)

    if argc == 1:
        text = sys.stdin.read()
    else:
        filename = argv[1]
        try:
            with open(filename) as f:
                text = f.read()
        except FileNotFoundError:
            print(f"File {filename} not found", file=sys.stderr)
            sys.exit(2)


    err, res = arbac_parser.parse(text)
    if err:
        print("Parse error: unexpected token", file=sys.stderr)
        print(res)          # print contextual help (string pinpointing the error in the text)
        sys.exit(3)

    res = typing.cast(ArbacReachability, res)

    print("Original ARBAC")
    print(res)

    print("Forward sliced ARBAC")
    print(pruning.forward_slicing(res))

    print("Backward sliced ARBAC")
    print(pruning.backward_slicing(res))

    print("Sliced ARBAC")
    print(pruning.slicing(res))


if __name__ == "__main__":
    main(sys.argv)

