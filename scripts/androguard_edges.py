"""Dump androguard's invoke xrefs for one DEX, in the same TSV shape as
`spike edges`: caller \t callee \t byte offset.

usage: python androguard_edges.py <classesN.dex>   (needs androguard 4.x)
"""

import sys

from loguru import logger

logger.disable("androguard")

from androguard.core.analysis.analysis import Analysis  # noqa: E402
from androguard.core.dex import DEX  # noqa: E402


def sig(m) -> str:
    # androguard renders descriptors with spaces between params: "(I Z)V"
    return f"{m.class_name}->{m.name}{m.descriptor.replace(' ', '')}"


def main() -> None:
    with open(sys.argv[1], "rb") as f:
        d = DEX(f.read())
    dx = Analysis(d)
    dx.create_xref()
    out = sys.stdout
    for ma in dx.get_methods():
        if ma.is_external():
            continue
        caller = sig(ma)
        for _cls, callee, off in ma.get_xref_to():
            out.write(f"{caller}\t{sig(callee)}\t{off}\n")


if __name__ == "__main__":
    main()
