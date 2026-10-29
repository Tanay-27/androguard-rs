"""Dump every instruction's androguard text for one DEX, in the same shape as
`spike insns`: method \t offset \t get_name() \t get_output(), or
method \t ERR when androguard rejects the method's bytecode.

usage: python androguard_insns.py <classesN.dex>   (needs androguard 4.1.3)
"""

import sys

from loguru import logger

logger.disable("androguard")

from androguard.core.dex import DEX  # noqa: E402


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def main() -> None:
    with open(sys.argv[1], "rb") as f:
        d = DEX(f.read())
    out = open(sys.stdout.fileno(), "w", encoding="utf-8", errors="backslashreplace", closefd=False)
    for cls in d.get_classes():
        for m in cls.get_methods():
            if m.get_code() is None:
                continue
            sig = esc(f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor().replace(' ', '')}")
            try:
                decoded = list(m.get_instructions_idx())
            except Exception as e:
                out.write(f"{sig}\tERR\t{esc(str(e))}\n")
                continue
            for off, ins in decoded:
                out.write(f"{sig}\t{off}\t{ins.get_name()}\t{esc(str(ins.get_output()))}\n")
    out.flush()


if __name__ == "__main__":
    main()
