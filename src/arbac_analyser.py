#!/usr/bin/env python3

"""ARBAC analyser: role reachability verifier.

TODO: describe how to use this from cli
"""


import sys
from typing import List
from src.parser import arbac_parser


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

    print(res)


if __name__ == "__main__":
    main(sys.argv)

