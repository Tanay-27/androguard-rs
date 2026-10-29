"""Dump androguard 4.1.3's class metadata for one DEX, in the same shape as
`spike classes`:
  C \t class \t access flags \t superclass \t interfaces (comma-joined)
  M \t class \t name \t descriptor \t access flags
  F \t class \t access flags \t name \t descriptor \t repr(init value)
The F line's last field is repr() of the init value with object
addresses blanked, as Apk.class_info() renders it.

usage: python androguard_classes.py <classesN.dex>   (needs androguard 4.1.3)
"""

import re
import sys

from loguru import logger

logger.disable("androguard")

from androguard.core.dex import DEX  # noqa: E402

# EncodedArray/EncodedAnnotation values repr() as Python objects with a memory
# address; it's not reproducible run to run, so blank it on both sides.
ADDR = re.compile(r" at 0x[0-9a-f]+>")


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def init_text(field) -> str:
    init_value = getattr(field, "init_value", None)
    if init_value is None:
        return "<no encoded init value>"
    value = getattr(init_value, "value", init_value)
    return ADDR.sub(" at 0x0>", repr(value))


def main() -> None:
    with open(sys.argv[1], "rb") as f:
        d = DEX(f.read())
    out = open(sys.stdout.fileno(), "w", encoding="utf-8", errors="backslashreplace", closefd=False)

    def line(*fields: str) -> None:
        out.write("\t".join(esc(str(x)) for x in fields) + "\n")

    for cd in d.get_classes():
        name = cd.get_name()
        line("C", name, cd.get_access_flags_string(), cd.get_superclassname(), ",".join(cd.get_interfaces()))
        for m in cd.get_methods():
            line("M", name, m.get_name(), m.get_descriptor(), m.get_access_flags_string())
        for fld in cd.get_fields():
            line("F", name, fld.get_access_flags_string(), fld.get_name(), fld.get_descriptor(), init_text(fld))
    out.flush()


if __name__ == "__main__":
    main()
