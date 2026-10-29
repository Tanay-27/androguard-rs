"""androguard 4.1.3's load exceptions, built from the native side's recipes.

``androguard_core::agload`` finds what androguard's ``DEX()``,
``Analysis.add()`` and ``create_xref()`` raise for a DEX file and describes
it as a tuple; ``make()`` builds the same exception (type, ``args``,
``str()``). Enum errors are raised by calling an enum of the same name and
qualified name as androguard's, so the message is the running Python's.
"""

from __future__ import annotations

import struct
import sys
from enum import IntEnum

__all__ = ["TypeMapItem", "HiddenApiClassDataItem", "make", "max_depth", "c_units"]


class TypeMapItem(IntEnum):
    """``androguard.core.dex.dex_types.TypeMapItem``."""

    HEADER_ITEM = 0x0
    STRING_ID_ITEM = 0x1
    TYPE_ID_ITEM = 0x2
    PROTO_ID_ITEM = 0x3
    FIELD_ID_ITEM = 0x4
    METHOD_ID_ITEM = 0x5
    CLASS_DEF_ITEM = 0x6
    CALL_SITE_ITEM = 0x7
    METHOD_HANDLE_ITEM = 0x8
    MAP_LIST = 0x1000
    TYPE_LIST = 0x1001
    ANNOTATION_SET_REF_LIST = 0x1002
    ANNOTATION_SET_ITEM = 0x1003
    CLASS_DATA_ITEM = 0x2000
    CODE_ITEM = 0x2001
    STRING_DATA_ITEM = 0x2002
    DEBUG_INFO_ITEM = 0x2003
    ANNOTATION_ITEM = 0x2004
    ENCODED_ARRAY_ITEM = 0x2005
    ANNOTATIONS_DIRECTORY_ITEM = 0x2006
    HIDDENAPI_CLASS_DATA_ITEM = 0xF000


class HiddenApiClassDataItem:
    """Holds androguard's two flag enums (their qualified names appear in
    its ValueError messages)."""

    class RestrictionApiFlag(IntEnum):
        WHITELIST = 0
        GREYLIST = 1
        BLACKLIST = 2
        GREYLIST_MAX_O = 3
        GREYLIST_MAX_P = 4
        GREYLIST_MAX_Q = 5
        GREYLIST_MAX_R = 6

    class DomapiApiFlag(IntEnum):
        NONE = 0
        CORE_PLATFORM_API = 1
        TEST_API = 2


_ENUMS = {
    "TypeMapItem": TypeMapItem,
    "RestrictionApiFlag": HiddenApiClassDataItem.RestrictionApiFlag,
    "DomapiApiFlag": HiddenApiClassDataItem.DomapiApiFlag,
}


def make(r) -> BaseException:
    """The exception a recipe from the native side stands for."""
    k = r[0]
    if k == "Header":
        return (NotImplementedError if r[1] else ValueError)(r[2])
    if k == "Struct":
        return struct.error(f"unpack requires a buffer of {r[1]} bytes")
    if k == "KeyMap":
        return KeyError(TypeMapItem(r[1]))
    if k == "KeyInt":
        return KeyError(r[1])
    if k == "Enum":
        try:
            _ENUMS[r[1]](r[2])
        except ValueError as e:
            return ValueError(*e.args)
        raise AssertionError(r)
    if k == "IndexList":
        return IndexError("list index out of range")
    if k == "IndexStr":
        return IndexError("string index out of range")
    if k == "Attr":
        return AttributeError(f"'{r[1]}' object has no attribute '{r[2]}'")
    if k == "Recursion":
        return RecursionError("maximum recursion depth exceeded")
    if k == "NoTerminate":
        # androguard loops forever reading the string (its list of empty
        # reads grows until memory runs out).
        return MemoryError()
    if k == "Invalid":
        return r[1]
    raise AssertionError(r)


def max_depth(frame) -> int:
    """Frames androguard's code may go deeper than ``frame`` (the frame
    standing for androguard's ``DEX.__init__``) before RecursionError."""
    n = 0
    f = frame
    while f is not None:
        n += 1
        f = f.f_back
    return sys.getrecursionlimit() - n


class _CProbe:
    __slots__ = ()

    def __init__(self, box):
        box[0] += 1
        _CProbe(box)


def c_units() -> int:
    """C recursion units CPython has left at the caller's frame.

    Python 3.12 also limits C recursion, separately from the recursion
    limit: every nested instantiation counts two units (``type.__call__``,
    and the eval loop entered for ``__init__``), a property getter or
    ``__getitem__`` run from C one. androguard's nested encoded values are
    nested instantiations, so with the recursion limit at 5000 (as importing
    ``androguard.misc`` or ``androguard.decompiler`` sets it) this is the
    limit they hit. Measured by nesting instantiations until RecursionError,
    with the recursion limit raised meanwhile so that only the C limit
    stops it."""
    old = sys.getrecursionlimit()
    box = [0]
    sys.setrecursionlimit(max(old, 1_000_000))
    try:
        _CProbe(box)
    except RecursionError:
        pass
    finally:
        sys.setrecursionlimit(old)
    return 2 * box[0] + 1
