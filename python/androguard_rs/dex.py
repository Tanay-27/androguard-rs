"""androguard 4.1.3's instruction classes (``androguard.core.dex``), for the
objects ``EncodedMethod.get_instructions()``, ``get_instruction()`` and
``get_code().get_bc().get_instructions()`` return in ``androguard_rs``'s
facade (``androguard_rs._analysis``).

Swap the import and ``isinstance`` checks keep working::

    # from androguard.core.dex import Instruction, Instruction11n, Instruction21s, Instruction31i
    from androguard_rs.dex import Instruction, Instruction11n, Instruction21s, Instruction31i

Every class androguard 4.1.3 has for DEX bytecode is here under the same
name, with the same public methods and the same format fields (``A``,
``B``, ``AA``, ``BBBB``, ``BBBBBBBB``, ...), whose values are unpacked from
the instruction's bytes with the struct formats androguard's constructors
use, so signs, widths and quirks match (``Instruction21h.BBBB`` is the
shifted value, ``Instruction11n.B`` is sign-extended, 31c's index is a
signed int, so ``get_raw()`` of a const-string/jumbo with an index of 2**31
or more raises ``struct.error`` as androguard's does). The payloads
(``PackedSwitch``, ``SparseSwitch``, ``FillArrayData``) aren't
``Instruction`` subclasses, as in androguard, and lack ``get_kind()``/
``get_translated_kind()`` (AttributeError).

The text (``get_output()``) and the resolved reference
(``get_translated_kind()``, the kind text in ``get_operands()``) come from
the native decoder; nothing else needs the DEX. Two things would: ``cm``
(androguard's ClassManager) and ``get_raw_string()`` (which reads the index
as a string index whatever the opcode); they raise NotImplementedError and
are counted in ``GAPS``. Unknown attributes raise AttributeError, as in
androguard.

Objects are built per method, on demand, from one native call
(``androguard_rs.Apk.instructions(sig)``); fields are unpacked on first
access. Not reproduced: ``repr()`` (androguard's default object repr shows
a memory address, and this module's name), and notes added with
``add_note()`` on a payload last only as long as the method's instruction
list stays in the facade's cache.
"""

from __future__ import annotations

import binascii
import struct
from collections import Counter
from enum import IntEnum

from . import _native

InvalidInstruction = _native.InvalidInstruction

__all__ = [
    "Kind", "Operand", "InvalidInstruction", "Instruction", "PackedSwitch", "SparseSwitch", "FillArrayData",
    "DALVIK_OPCODES_FORMAT", "DALVIK_OPCODES_PAYLOAD", "GAPS", "NOTES", "get_kind", "get_type",
    "DEX", "ClassDefItem", "EncodedMethod", "EncodedField", "EncodedValue", "DalvikCode", "DCode", "ClassManager",
]

#: attribute -> times something asked for it and got NotImplementedError.
GAPS: Counter = Counter()


def _gap(owner: str, attr: str):
    key = f"{owner}.{attr}"
    GAPS[key] += 1
    raise NotImplementedError(f"androguard_rs.dex: {key} is not implemented")


class Kind(IntEnum):
    """androguard.core.dex.dex_types.Kind"""

    METH = 0
    STRING = 1
    FIELD = 2
    TYPE = 3
    PROTO = 9
    METH_PROTO = 10
    CALL_SITE = 11
    VARIES = 4
    INLINE_METHOD = 5
    VTABLE_OFFSET = 6
    FIELD_OFFSET = 7
    RAW_STRING = 8


class Operand(IntEnum):
    """androguard.core.dex.dex_types.Operand"""

    REGISTER = 0
    LITERAL = 1
    RAW = 2
    OFFSET = 3
    KIND = 0x100


def _s(fmt: str) -> struct.Struct:
    return struct.Struct("<" + fmt)


_B2, _Bb, _BBh, _BBH, _BBi, _BBq, _BBHH, _BBBB, _BBBb = (
    _s("BB"), _s("Bb"), _s("BBh"), _s("BBH"), _s("BBi"), _s("BBq"), _s("BBHH"), _s("BBBB"), _s("BBBb"))
_h, _H, _Hh, _2H, _3H, _Hi, _HI, _BBHHH, _HIH, _HI2H = (
    _s("h"), _s("H"), _s("Hh"), _s("2H"), _s("3H"), _s("Hi"), _s("HI"), _s("BBHHH"), _s("HIH"), _s("HI2H"))
_l, _2HI, _2Hi, _2Hs = _s("l"), _s("2HI"), _s("2Hi"), _s("2H")


def get_kind(cm, kind: int, value: int):
    """androguard.core.dex.get_kind needs the ClassManager; references are
    resolved natively instead (``Instruction.get_translated_kind()``)."""
    _gap("dex", "get_kind")


# ── Instruction ───────────────────────────────────────────────────────────────

# A row from androguard_rs.Apk.instructions(): (offset, op_value, length,
# raw_len, output, kind).
_OFF, _OP, _LEN, _RAWLEN, _OUT, _KINDTXT = range(6)

_NOT_IMPLEMENTED = ("cm", "CM")


class Instruction:
    """androguard.core.dex.Instruction."""

    __slots__ = ("_code", "_row", "_f")

    length = 0
    #: Format fields, unpacked from the bytes on first access.
    _FIELDS: tuple = ()
    #: The class overrides get_ref_kind() (which then never raises).
    _HAS_REF = False

    def _unpack(self, raw: bytes) -> dict:
        return {}

    def __getattr__(self, attr):
        if attr in self._FIELDS:
            f = self._f
            if f is None:
                row = self._row
                off = row[_OFF]
                f = self._f = self._unpack(self._code[off:off + row[_RAWLEN]])
            return f[attr]
        if attr == "OP":
            return self._row[_OP]
        if attr in _NOT_IMPLEMENTED:
            _gap(type(self).__name__, attr)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{attr}'")

    def get_kind(self) -> int:
        return DALVIK_OPCODES_FORMAT[self._row[_OP]][1][1]

    def get_name(self) -> str:
        return _NAMES[self._row[_OP]]

    def get_op_value(self) -> int:
        return self._row[_OP]

    def get_literals(self) -> list:
        return []

    def show(self, idx: int) -> None:
        print(self.get_name() + " " + self.get_output(idx), end=' ')

    def show_buff(self, idx: int) -> str:
        return self.get_output(idx)

    def get_translated_kind(self) -> str:
        # androguard: get_kind(self.cm, self.get_kind(), self.get_ref_kind()),
        # so a missing kind is IndexError before get_ref_kind() can raise.
        self.get_kind()
        if not self._HAS_REF:
            self.get_ref_kind()  # raises, as androguard's base class does
        return self._row[_KINDTXT]

    def get_output(self, idx: int = -1) -> str:
        return self._row[_OUT]

    def get_operands(self, idx: int = -1) -> list:
        return []

    def get_length(self) -> int:
        return self.length

    def get_raw(self):
        raise Exception("not implemented")

    def get_ref_kind(self):
        raise Exception("not implemented")

    def get_hex(self) -> str:
        s = binascii.hexlify(self.get_raw()).decode('ascii')
        return " ".join(s[i: i + 2] for i in range(0, len(s), 2))

    def __str__(self):
        return "{} {}".format(self.get_name(), self.get_output())

    def disasm(self) -> str:
        s = binascii.hexlify(self.get_raw()).decode('ascii')
        byteview = " ".join(s[i: i + 4] for i in range(0, len(s), 4))
        return '{:24s}  {:24s} {}'.format(byteview, self.get_name(), self.get_output())


def _kind_tuple(self, ref):
    return (self.get_kind() + Operand.KIND, ref, self._row[_KINDTXT])


class _Kinded(Instruction):
    """Instructions with get_string()/get_raw_string() (21c, 31c)."""

    __slots__ = ()

    def get_string(self) -> str:
        self.get_kind()
        return self._row[_KINDTXT]

    def get_raw_string(self) -> str:
        _gap(type(self).__name__, "get_raw_string")


class Instruction35c(Instruction):
    __slots__ = ()
    _HAS_REF = True
    length = 6
    _FIELDS = ("BBBB", "G", "A", "C", "D", "E", "F")

    def _unpack(self, raw):
        i16a, BBBB, i16b = _3H.unpack(raw[:6])
        return dict(BBBB=BBBB, G=(i16a >> 8) & 0xF, A=(i16a >> 12) & 0xF, C=i16b & 0xF, D=(i16b >> 4) & 0xF,
                    E=(i16b >> 8) & 0xF, F=(i16b >> 12) & 0xF)

    def get_operands(self, idx: int = -1) -> list:
        A = self.A
        if A > 5:
            return []
        regs = [self.C, self.D, self.E, self.F, self.G][:A]
        return [(Operand.REGISTER, r) for r in regs] + [_kind_tuple(self, self.BBBB)]

    def get_ref_kind(self) -> int:
        return self.BBBB

    def get_raw(self) -> bytes:
        return _3H.pack((self.A << 12) | (self.G << 8) | self.OP, self.BBBB,
                        (self.F << 12) | (self.E << 8) | (self.D << 4) | self.C)


class Instruction10x(Instruction):
    __slots__ = ()
    length = 2

    def get_raw(self) -> bytes:
        return _H.pack(self.OP)


class Instruction21h(Instruction):
    __slots__ = ()
    length = 4
    _FIELDS = ("AA", "BBBB", "_Instruction21h__BBBB")

    def _unpack(self, raw):
        OP, AA, raw_bbbb = _BBh.unpack(raw[:4])
        if OP == 0x15:
            BBBB = raw_bbbb << 16
        elif OP == 0x19:
            BBBB = raw_bbbb << 48
        else:
            BBBB = raw_bbbb
        return {"AA": AA, "BBBB": BBBB, "_Instruction21h__BBBB": raw_bbbb}

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.LITERAL, self.BBBB)]

    def get_literals(self) -> list:
        return [self.BBBB]

    def get_raw(self) -> bytes:
        return _Hh.pack((self.AA << 8) | self.OP, self.__BBBB)


class Instruction11n(Instruction):
    __slots__ = ()
    length = 2
    _FIELDS = ("A", "B")

    def _unpack(self, raw):
        _op, i8 = _Bb.unpack(raw[:2])
        return dict(A=i8 & 0xF, B=i8 >> 4)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.A), (Operand.LITERAL, self.B)]

    def get_literals(self) -> list:
        return [self.B]

    def get_raw(self) -> bytes:
        return _h.pack((self.B << 12) | (self.A << 8) | self.OP)


class Instruction21c(_Kinded):
    __slots__ = ()
    _HAS_REF = True
    length = 4
    _FIELDS = ("AA", "BBBB")

    def _unpack(self, raw):
        _op, AA, BBBB = _BBH.unpack(raw[:4])
        return dict(AA=AA, BBBB=BBBB)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), _kind_tuple(self, self.BBBB)]

    def get_ref_kind(self) -> int:
        return self.BBBB

    def get_raw(self) -> bytes:
        return _2H.pack((self.AA << 8) | self.OP, self.BBBB)


class Instruction21s(Instruction):
    __slots__ = ()
    length = 4
    _FIELDS = ("AA", "BBBB")

    def _unpack(self, raw):
        _op, AA, BBBB = _BBh.unpack(raw[:4])
        return dict(AA=AA, BBBB=BBBB)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.LITERAL, self.BBBB)]

    def get_literals(self) -> list:
        return [self.BBBB]

    def get_raw(self) -> bytes:
        return _BBh.pack(self.OP, self.AA, self.BBBB)


class _RegsAB(Instruction):
    """i16 = (B << 12) | (A << 8) | OP, then a 16-bit CCCC."""

    __slots__ = ()
    length = 4
    _FIELDS = ("A", "B", "CCCC")
    _CCCC = _2H

    def _unpack(self, raw):
        i16, CCCC = self._CCCC.unpack(raw[:4])
        return dict(A=(i16 >> 8) & 0xF, B=(i16 >> 12) & 0xF, CCCC=CCCC)


class Instruction22c(_RegsAB):
    __slots__ = ()
    _HAS_REF = True

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.A), (Operand.REGISTER, self.B), _kind_tuple(self, self.CCCC)]

    def get_ref_kind(self) -> int:
        return self.CCCC

    def get_raw(self) -> bytes:
        return _2H.pack((self.B << 12) | (self.A << 8) | self.OP, self.CCCC)


class Instruction22cs(Instruction22c):
    __slots__ = ()


class Instruction31t(Instruction):
    __slots__ = ()
    length = 6
    _FIELDS = ("AA", "BBBBBBBB")

    def _unpack(self, raw):
        _op, AA, B = _BBi.unpack(raw[:6])
        return dict(AA=AA, BBBBBBBB=B)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.OFFSET, self.BBBBBBBB)]

    def get_ref_off(self) -> int:
        return self.BBBBBBBB

    def get_raw(self) -> bytes:
        return _Hi.pack((self.AA << 8) | self.OP, self.BBBBBBBB)


class Instruction31c(_Kinded):
    __slots__ = ()
    _HAS_REF = True
    length = 6
    _FIELDS = ("AA", "BBBBBBBB")

    def _unpack(self, raw):
        _op, AA, B = _BBi.unpack(raw[:6])
        return dict(AA=AA, BBBBBBBB=B)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), _kind_tuple(self, self.BBBBBBBB)]

    def get_ref_kind(self) -> int:
        return self.BBBBBBBB

    def get_raw(self) -> bytes:
        return _HI.pack((self.AA << 8) | self.OP, self.BBBBBBBB)


class Instruction12x(Instruction):
    __slots__ = ()
    length = 2
    _FIELDS = ("A", "B")

    def _unpack(self, raw):
        (i16,) = _h.unpack(raw[:2])
        return dict(A=(i16 >> 8) & 0xF, B=(i16 >> 12) & 0xF)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.A), (Operand.REGISTER, self.B)]

    def get_raw(self) -> bytes:
        return _H.pack((self.B << 12) | (self.A << 8) | self.OP)


class Instruction11x(Instruction):
    __slots__ = ()
    length = 2
    _FIELDS = ("AA",)

    def _unpack(self, raw):
        return dict(AA=raw[1])

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA)]

    def get_raw(self) -> bytes:
        return _H.pack((self.AA << 8) | self.OP)


class Instruction51l(Instruction):
    __slots__ = ()
    length = 10
    _FIELDS = ("AA", "BBBBBBBBBBBBBBBB")

    def _unpack(self, raw):
        _op, AA, B = _BBq.unpack(raw[:10])
        return dict(AA=AA, BBBBBBBBBBBBBBBB=B)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.LITERAL, self.BBBBBBBBBBBBBBBB)]

    def get_literals(self) -> list:
        return [self.BBBBBBBBBBBBBBBB]

    def get_raw(self) -> bytes:
        return _BBq.pack(self.OP, self.AA, self.BBBBBBBBBBBBBBBB)


class Instruction31i(Instruction):
    __slots__ = ()
    length = 6
    _FIELDS = ("AA", "BBBBBBBB")

    def _unpack(self, raw):
        _op, AA, B = _BBi.unpack(raw[:6])
        return dict(AA=AA, BBBBBBBB=B)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.LITERAL, self.BBBBBBBB)]

    def get_literals(self) -> list:
        return [self.BBBBBBBB]

    def get_raw(self) -> bytes:
        return _BBi.pack(self.OP, self.AA, self.BBBBBBBB)


class Instruction22x(Instruction):
    __slots__ = ()
    length = 4
    _FIELDS = ("AA", "BBBB")

    def _unpack(self, raw):
        _op, AA, BBBB = _BBH.unpack(raw[:4])
        return dict(AA=AA, BBBB=BBBB)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.REGISTER, self.BBBB)]

    def get_raw(self) -> bytes:
        return _2H.pack((self.AA << 8) | self.OP, self.BBBB)


class Instruction23x(Instruction):
    __slots__ = ()
    length = 4
    _FIELDS = ("AA", "BB", "CC")

    def _unpack(self, raw):
        _op, AA, BB, CC = _BBBB.unpack(raw[:4])
        return dict(AA=AA, BB=BB, CC=CC)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.REGISTER, self.BB), (Operand.REGISTER, self.CC)]

    def get_raw(self) -> bytes:
        return _2H.pack((self.AA << 8) | self.OP, (self.CC << 8) | self.BB)


class Instruction20t(Instruction):
    __slots__ = ()
    length = 4
    _FIELDS = ("AAAA",)

    def _unpack(self, raw):
        _op, _pad, AAAA = _BBh.unpack(raw[:4])
        return dict(AAAA=AAAA)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.OFFSET, self.AAAA)]

    def get_ref_off(self) -> int:
        return self.AAAA

    def get_raw(self) -> bytes:
        return _Hh.pack(self.OP, self.AAAA)


class Instruction21t(Instruction):
    __slots__ = ()
    length = 4
    _FIELDS = ("AA", "BBBB")

    def _unpack(self, raw):
        _op, AA, BBBB = _BBh.unpack(raw[:4])
        return dict(AA=AA, BBBB=BBBB)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.OFFSET, self.BBBB)]

    def get_ref_off(self) -> int:
        return self.BBBB

    def get_raw(self) -> bytes:
        return _Hh.pack((self.AA << 8) | self.OP, self.BBBB)


class Instruction10t(Instruction):
    __slots__ = ()
    length = 2
    _FIELDS = ("AA",)

    def _unpack(self, raw):
        _op, AA = _Bb.unpack(raw[:2])
        return dict(AA=AA)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.OFFSET, self.AA)]

    def get_ref_off(self) -> int:
        return self.AA

    def get_raw(self) -> bytes:
        return _Bb.pack(self.OP, self.AA)


class Instruction22t(_RegsAB):
    __slots__ = ()
    _CCCC = _Hh

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.A), (Operand.REGISTER, self.B), (Operand.OFFSET, self.CCCC)]

    def get_ref_off(self) -> int:
        return self.CCCC

    def get_raw(self) -> bytes:
        return _Hh.pack((self.B << 12) | (self.A << 8) | self.OP, self.CCCC)


class Instruction22s(_RegsAB):
    __slots__ = ()
    _CCCC = _Hh

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.A), (Operand.REGISTER, self.B), (Operand.LITERAL, self.CCCC)]

    def get_literals(self) -> list:
        return [self.CCCC]

    def get_raw(self) -> bytes:
        return _Hh.pack((self.B << 12) | (self.A << 8) | self.OP, self.CCCC)


class Instruction22b(Instruction):
    __slots__ = ()
    length = 4
    _FIELDS = ("AA", "BB", "CC")

    def _unpack(self, raw):
        _op, AA, BB, CC = _BBBb.unpack(raw[:4])
        return dict(AA=AA, BB=BB, CC=CC)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AA), (Operand.REGISTER, self.BB), (Operand.LITERAL, self.CC)]

    def get_literals(self) -> list:
        return [self.CC]

    def get_raw(self) -> bytes:
        return _Hh.pack((self.AA << 8) | self.OP, (self.CC << 8) | self.BB)


class Instruction30t(Instruction):
    __slots__ = ()
    length = 6
    _FIELDS = ("AAAAAAAA",)

    def _unpack(self, raw):
        _op, _pad, A = _BBi.unpack(raw[:6])
        return dict(AAAAAAAA=A)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.OFFSET, self.AAAAAAAA)]

    def get_ref_off(self) -> int:
        return self.AAAAAAAA

    def get_raw(self) -> bytes:
        return _Hi.pack(self.OP, self.AAAAAAAA)


class Instruction3rc(Instruction):
    __slots__ = ()
    _HAS_REF = True
    length = 6
    _FIELDS = ("AA", "BBBB", "CCCC", "NNNN")

    def _unpack(self, raw):
        _op, AA, BBBB, CCCC = _BBHH.unpack(raw[:6])
        return dict(AA=AA, BBBB=BBBB, CCCC=CCCC, NNNN=CCCC + AA - 1)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, i) for i in range(self.CCCC, self.NNNN + 1)] + [_kind_tuple(self, self.BBBB)]

    def get_ref_kind(self) -> int:
        return self.BBBB

    def get_raw(self) -> bytes:
        return _3H.pack((self.AA << 8) | self.OP, self.BBBB, self.CCCC)


class Instruction32x(Instruction):
    __slots__ = ()
    length = 6
    _FIELDS = ("AAAA", "BBBB")

    def _unpack(self, raw):
        _op, _pad, AAAA, BBBB = _BBHH.unpack(raw[:6])
        return dict(AAAA=AAAA, BBBB=BBBB)

    def get_operands(self, idx: int = -1) -> list:
        return [(Operand.REGISTER, self.AAAA), (Operand.REGISTER, self.BBBB)]

    def get_raw(self) -> bytes:
        return _3H.pack(self.OP, self.AAAA, self.BBBB)


class Instruction45cc(Instruction):
    __slots__ = ()
    length = 8
    _FIELDS = ("BBBB", "HHHH", "A", "G", "D", "C", "F", "E")

    def _unpack(self, raw):
        _op, reg1, BBBB, reg2, HHHH = _BBHHH.unpack(raw[:8])
        return dict(BBBB=BBBB, HHHH=HHHH, A=(reg1 & 0xF0) >> 4, G=reg1 & 0x0F, D=(reg2 & 0xF0) >> 4, C=reg2 & 0x0F,
                    F=(reg2 & 0xF000) >> 12, E=(reg2 & 0x0F00) >> 8)

    def get_raw(self) -> bytes:
        return _BBHHH.pack(self.OP, self.A << 4 | self.G, self.BBBB,
                           self.F << 12 | self.E << 8 | self.D << 4 | self.C, self.HHHH)

    def get_operands(self):
        pass


class Instruction4rcc(Instruction):
    __slots__ = ()
    length = 8
    _FIELDS = ("AA", "BBBB", "CCCC", "HHHH", "NNNN")

    def _unpack(self, raw):
        _op, AA, BBBB, CCCC, HHHH = _BBHHH.unpack(raw[:8])
        return dict(AA=AA, BBBB=BBBB, CCCC=CCCC, HHHH=HHHH, NNNN=AA + CCCC - 1)

    def get_raw(self) -> bytes:
        return _BBHHH.pack(self.OP, self.AA, self.BBBB, self.CCCC, self.HHHH)

    def get_operands(self):
        pass


class Instruction00x(Instruction):
    """Unused opcodes: androguard raises InvalidInstruction on these, so no
    object of this class is ever produced."""

    __slots__ = ()
    length = 0


# ODEX-only formats: androguard 4.1.3 maps no DEX opcode to them (and
# androguard_rs reads DEX, not ODEX), so no object of these classes is ever
# produced; they exist so imports and isinstance checks work.
class Instruction20bc(Instruction):
    __slots__ = ()
    length = 4


class Instruction35mi(Instruction):
    __slots__ = ()
    length = 6


class Instruction35ms(Instruction):
    __slots__ = ()
    length = 6


class Instruction3rmi(Instruction):
    __slots__ = ()
    length = 6


class Instruction3rms(Instruction):
    __slots__ = ()
    length = 6


class Instruction41c(Instruction):
    __slots__ = ()
    length = 8


class Instruction40sc(Instruction):
    __slots__ = ()
    length = 8


class Instruction52c(Instruction):
    __slots__ = ()
    length = 10


class Instruction5rc(Instruction):
    __slots__ = ()
    length = 10


# ── Payloads ──────────────────────────────────────────────────────────────────


class _Payload:
    """Shared plumbing of androguard's three payload classes (which aren't
    Instruction subclasses and share no base)."""

    __slots__ = ("_code", "_row", "_f", "notes")

    OP = 0
    _FIELDS: tuple = ()
    format_general_size = 0

    def __getattr__(self, attr):
        if attr in self._FIELDS:
            f = self._f
            if f is None:
                row = self._row
                off = row[_OFF]
                f = self._f = self._unpack(self._code[off:off + row[_RAWLEN]])
            return f[attr]
        if attr == "notes":
            self.notes = []
            return self.notes
        if attr in _NOT_IMPLEMENTED:
            _gap(type(self).__name__, attr)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{attr}'")

    def add_note(self, msg: str) -> None:
        self.notes.append(msg)

    def get_notes(self) -> list:
        return self.notes

    def get_op_value(self) -> int:
        return self.ident

    def get_formatted_operands(self) -> None:
        return None

    def show(self, pos) -> None:
        print(self.show_buff(pos), end=' ')

    def get_hex(self) -> str:
        s = binascii.hexlify(self.get_raw()).decode("ascii")
        return " ".join(s[i: i + 2] for i in range(0, len(s), 2))

    def disasm(self) -> str:
        return self.show_buff(None)


class FillArrayData(_Payload):
    __slots__ = ()
    format_general_size = 8
    _FIELDS = ("ident", "element_width", "size", "data")

    def _unpack(self, raw):
        ident, element_width, size = _2HI.unpack(raw[0:8])
        return dict(ident=ident, element_width=element_width, size=size, data=raw[8:])

    def get_data(self) -> bytes:
        return self.data

    def get_output(self, idx: int = -1) -> str:
        return self._row[_OUT]

    def get_operands(self, idx: int = -1):
        if isinstance(self.get_data(), bytearray):
            return [(Operand.RAW, binascii.hexlify(self.get_data()).decode('ascii'))]
        return [(Operand.RAW, repr(self.get_data()))]

    def get_name(self) -> str:
        return "fill-array-data-payload"

    def show_buff(self, pos: int) -> str:
        buff = self.get_name() + " "
        for i in range(0, len(self.data)):
            buff += "\\x%02x" % self.data[i]
        return buff

    def get_length(self) -> int:
        return ((self.size * self.element_width + 1) // 2 + 4) * 2

    def get_raw(self) -> bytes:
        return _2HI.pack(self.ident, self.element_width, self.size) + self.data


class SparseSwitch(_Payload):
    __slots__ = ()
    format_general_size = 4
    _FIELDS = ("ident", "size", "keys", "targets")

    def _unpack(self, raw):
        ident, size = _2Hs.unpack(raw[0:4])
        vals = [v for (v,) in _l.iter_unpack(raw[4:4 + 8 * size])]
        return dict(ident=ident, size=size, keys=vals[:size], targets=vals[size:])

    def get_keys(self) -> list:
        return self.keys

    def get_values(self) -> list:
        return self.get_keys()

    def get_targets(self) -> list:
        return self.targets

    def get_output(self, idx: int = -1) -> str:
        return self._row[_OUT]

    def get_operands(self, idx: int = -1):
        return []

    def get_name(self) -> str:
        return "sparse-switch-payload"

    def show_buff(self, pos: int) -> str:
        buff = self.get_name() + " "
        for i in range(0, len(self.keys)):
            buff += "{:x}:{:x} ".format(self.keys[i], self.targets[i])
        return buff

    def get_length(self) -> int:
        return self.format_general_size + (self.size * 4) * 2

    def get_raw(self) -> bytes:
        return (_2Hs.pack(self.ident, self.size) + b''.join(_l.pack(i) for i in self.keys)
                + b''.join(_l.pack(i) for i in self.targets))


class PackedSwitch(_Payload):
    __slots__ = ()
    format_general_size = 8
    _FIELDS = ("ident", "size", "first_key", "targets")

    def _unpack(self, raw):
        ident, size, first_key = _2Hi.unpack(raw[0:8])
        # raw holds exactly the targets androguard reads (fewer than size
        # when size overruns the buffer).
        return dict(ident=ident, size=size, first_key=first_key, targets=[v for (v,) in _l.iter_unpack(raw[8:])])

    def get_keys(self) -> list:
        return [(self.first_key + i) for i in range(0, len(self.targets))]

    def get_values(self) -> list:
        return self.get_keys()

    def get_targets(self) -> list:
        return self.targets

    def get_output(self, idx: int = -1) -> str:
        return self._row[_OUT]

    def get_operands(self, idx: int = -1):
        return []

    def get_name(self) -> str:
        return "packed-switch-payload"

    def show_buff(self, pos: int) -> str:
        buff = self.get_name() + " "
        buff += "%x:" % self.first_key
        for i in self.targets:
            buff += " %x" % i
        return buff

    def get_length(self) -> int:
        return self.format_general_size + (self.size * 4)

    def get_raw(self) -> bytes:
        return _2Hi.pack(self.ident, self.size, self.first_key) + b''.join(_l.pack(i) for i in self.targets)


# ── Opcode tables (androguard 4.1.3's DALVIK_OPCODES_FORMAT) ──────────────────


def _table():
    t = {}

    def put(cls, ops, names, kind=None):
        for op, name in zip(ops, names.split()):
            t[op] = [cls, [name] if kind is None else [name, kind]]

    put(Instruction10x, [0x00], "nop")
    put(Instruction12x, [0x01, 0x04, 0x07], "move move-wide move-object")
    put(Instruction22x, [0x02, 0x05, 0x08], "move/from16 move-wide/from16 move-object/from16")
    put(Instruction32x, [0x03, 0x06, 0x09], "move/16 move-wide/16 move-object/16")
    put(Instruction11x, range(0x0a, 0x0e), "move-result move-result-wide move-result-object move-exception")
    put(Instruction10x, [0x0e], "return-void")
    put(Instruction11x, range(0x0f, 0x12), "return return-wide return-object")
    put(Instruction11n, [0x12], "const/4")
    put(Instruction21s, [0x13], "const/16")
    put(Instruction31i, [0x14], "const")
    put(Instruction21h, [0x15], "const/high16")
    put(Instruction21s, [0x16], "const-wide/16")
    put(Instruction31i, [0x17], "const-wide/32")
    put(Instruction51l, [0x18], "const-wide")
    put(Instruction21h, [0x19], "const-wide/high16")
    put(Instruction21c, [0x1a], "const-string", Kind.STRING)
    put(Instruction31c, [0x1b], "const-string/jumbo", Kind.STRING)
    put(Instruction21c, [0x1c], "const-class", Kind.TYPE)
    put(Instruction11x, [0x1d, 0x1e], "monitor-enter monitor-exit")
    put(Instruction21c, [0x1f], "check-cast", Kind.TYPE)
    put(Instruction22c, [0x20], "instance-of", Kind.TYPE)
    put(Instruction12x, [0x21], "array-length")
    put(Instruction21c, [0x22], "new-instance", Kind.TYPE)
    put(Instruction22c, [0x23], "new-array", Kind.TYPE)
    put(Instruction35c, [0x24], "filled-new-array", Kind.TYPE)
    put(Instruction3rc, [0x25], "filled-new-array/range", Kind.TYPE)
    put(Instruction31t, [0x26], "fill-array-data")
    put(Instruction11x, [0x27], "throw")
    put(Instruction10t, [0x28], "goto")
    put(Instruction20t, [0x29], "goto/16")
    put(Instruction30t, [0x2a], "goto/32")
    put(Instruction31t, [0x2b, 0x2c], "packed-switch sparse-switch")
    put(Instruction23x, range(0x2d, 0x32), "cmpl-float cmpg-float cmpl-double cmpg-double cmp-long")
    put(Instruction22t, range(0x32, 0x38), "if-eq if-ne if-lt if-ge if-gt if-le")
    put(Instruction21t, range(0x38, 0x3e), "if-eqz if-nez if-ltz if-gez if-gtz if-lez")
    put(Instruction00x, range(0x3e, 0x44), "unused unused unused unused unused unused")
    put(Instruction23x, range(0x44, 0x52),
        "aget aget-wide aget-object aget-boolean aget-byte aget-char aget-short "
        "aput aput-wide aput-object aput-boolean aput-byte aput-char aput-short")
    put(Instruction22c, range(0x52, 0x60),
        "iget iget-wide iget-object iget-boolean iget-byte iget-char iget-short "
        "iput iput-wide iput-object iput-boolean iput-byte iput-char iput-short", Kind.FIELD)
    put(Instruction21c, range(0x60, 0x6e),
        "sget sget-wide sget-object sget-boolean sget-byte sget-char sget-short "
        "sput sput-wide sput-object sput-boolean sput-byte sput-char sput-short", Kind.FIELD)
    put(Instruction35c, range(0x6e, 0x73),
        "invoke-virtual invoke-super invoke-direct invoke-static invoke-interface", Kind.METH)
    put(Instruction00x, [0x73], "unused")
    put(Instruction3rc, range(0x74, 0x79),
        "invoke-virtual/range invoke-super/range invoke-direct/range invoke-static/range invoke-interface/range",
        Kind.METH)
    put(Instruction00x, [0x79, 0x7a], "unused unused")
    put(Instruction12x, range(0x7b, 0x90),
        "neg-int not-int neg-long not-long neg-float neg-double int-to-long int-to-float int-to-double "
        "long-to-int long-to-float long-to-double float-to-int float-to-long float-to-double double-to-int "
        "double-to-long double-to-float int-to-byte int-to-char int-to-short")
    put(Instruction23x, range(0x90, 0xb0),
        "add-int sub-int mul-int div-int rem-int and-int or-int xor-int shl-int shr-int ushr-int "
        "add-long sub-long mul-long div-long rem-long and-long or-long xor-long shl-long shr-long ushr-long "
        "add-float sub-float mul-float div-float rem-float add-double sub-double mul-double div-double "
        "rem-double")
    put(Instruction12x, range(0xb0, 0xd0),
        "add-int/2addr sub-int/2addr mul-int/2addr div-int/2addr rem-int/2addr and-int/2addr or-int/2addr "
        "xor-int/2addr shl-int/2addr shr-int/2addr ushr-int/2addr add-long/2addr sub-long/2addr "
        "mul-long/2addr div-long/2addr rem-long/2addr and-long/2addr or-long/2addr xor-long/2addr "
        "shl-long/2addr shr-long/2addr ushr-long/2addr add-float/2addr sub-float/2addr mul-float/2addr "
        "div-float/2addr rem-float/2addr add-double/2addr sub-double/2addr mul-double/2addr "
        "div-double/2addr rem-double/2addr")
    put(Instruction22s, range(0xd0, 0xd8),
        "add-int/lit16 rsub-int mul-int/lit16 div-int/lit16 rem-int/lit16 and-int/lit16 or-int/lit16 "
        "xor-int/lit16")
    put(Instruction22b, range(0xd8, 0xe3),
        "add-int/lit8 rsub-int/lit8 mul-int/lit8 div-int/lit8 rem-int/lit8 and-int/lit8 or-int/lit8 "
        "xor-int/lit8 shl-int/lit8 shr-int/lit8 ushr-int/lit8")
    put(Instruction00x, range(0xe3, 0xfa), " ".join(["unused"] * 23))
    put(Instruction45cc, [0xfa], "invoke-polymorphic", Kind.METH_PROTO)
    put(Instruction4rcc, [0xfb], "invoke-polymorphic/range", Kind.METH_PROTO)
    put(Instruction35c, [0xfc], "invoke-custom", Kind.CALL_SITE)
    put(Instruction3rc, [0xfd], "invoke-custom/range", Kind.CALL_SITE)
    put(Instruction21c, [0xfe], "const-method-handle", Kind.METH)
    put(Instruction21c, [0xff], "const-method-type", Kind.PROTO)
    assert sorted(t) == list(range(256))
    return t


#: op -> [class, [name] or [name, Kind]], as androguard's.
DALVIK_OPCODES_FORMAT = _table()
DALVIK_OPCODES_PAYLOAD = {0x0100: [PackedSwitch], 0x0200: [SparseSwitch], 0x0300: [FillArrayData]}

_NAMES = [DALVIK_OPCODES_FORMAT[op][1][0] for op in range(256)]
_CLASSES = {op: e[0] for op, e in DALVIK_OPCODES_FORMAT.items()}
_CLASSES.update({op: e[0] for op, e in DALVIK_OPCODES_PAYLOAD.items()})


def _instructions(data) -> list:
    """Instruction objects for one `androguard_rs.Apk.instructions()` result
    ``(insns, rows)``, in order."""
    code, rows = data
    classes = _CLASSES
    new = object.__new__
    out = []
    append = out.append
    for row in rows:
        o = new(classes[row[1]])
        o._code = code
        o._row = row
        o._f = None
        append(o)
    return out


# ── DEX object model ──────────────────────────────────────────────────────────
#
# androguard 4.1.3's per-DEX objects (what a caller of DEX() gets and walks):
# DEX, ClassDefItem, EncodedMethod, EncodedField, EncodedValue, DalvikCode and
# DCode, served one class_def at a time from androguard_rs.Apk (dex_class(),
# code_instructions(), ...). Nothing per DEX is built up front: get_classes()
# is a list of light ClassDefItem objects (name only), a class's methods and
# fields are fetched when first asked for and kept in a bounded per-DEX LRU,
# and instructions in another. Objects compare (and hash) by what they stand
# for: an EncodedMethod/EncodedField by its DEX and its class_data entry, so
# one reached twice (or through a class_def sharing its class_data, or through
# a MethodAnalysis) is "the same object" for sets and dicts, as androguard's
# single objects are.
#
# Unknown attributes raise AttributeError, as androguard's objects do (callers
# may probe with getattr/try, e.g. `ClassDefItem.XREFfrom`); each is counted in
# NOTES.

from collections import OrderedDict  # noqa: E402
import re as _re  # noqa: E402
import threading as _threading  # noqa: E402

#: attribute -> times it was asked for and raised AttributeError, as in
#: androguard (informational).
NOTES: Counter = Counter()

_TYPE_DESCRIPTOR = {
    'V': 'void',
    'Z': 'boolean',
    'B': 'byte',
    'S': 'short',
    'C': 'char',
    'I': 'int',
    'J': 'long',
    'F': 'float',
    'D': 'double',
}


def get_type(atype: str, size=None) -> str:
    """androguard 4.1.3's ``androguard.core.dex.get_type``, verbatim."""
    if atype.startswith('java.lang'):
        atype = atype.replace('java.lang.', '')
    res = _TYPE_DESCRIPTOR.get(atype.lstrip('java.lang'))
    if res is None:
        if atype[0] == 'L':
            res = atype[1:-1].replace('/', '.')
        elif atype[0] == '[':
            if size is None:
                res = '%s[]' % get_type(atype[1:])
            else:
                res = '{}[{}]'.format(get_type(atype[1:]), size)
        else:
            res = atype
    return res


class _Quiet:
    """Base: unknown attributes raise AttributeError (counted in NOTES)."""

    __slots__ = ()

    def __getattr__(self, attr):
        if not (attr.startswith("__") and attr.endswith("__")):
            NOTES[f"{type(self).__name__}.{attr}"] += 1
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{attr}'")


class _LRU:
    """A small thread-safe LRU of computed values."""

    __slots__ = ("_d", "_n", "_lock")

    def __init__(self, n: int):
        self._d = OrderedDict()
        self._n = n
        self._lock = _threading.Lock()

    def get(self, key, make):
        with self._lock:
            v = self._d.get(key)
            if v is not None:
                self._d.move_to_end(key)
                return v
        v = make()
        with self._lock:
            v = self._d.setdefault(key, v)
            self._d.move_to_end(key)
            if len(self._d) > self._n:
                self._d.popitem(last=False)
        return v


class ClassManager(_Quiet):
    """androguard's ClassManager, as far as `EncodedMethod.CM.vm` goes."""

    __slots__ = ("vm",)

    def __init__(self, vm):
        self.vm = vm


class EncodedValue(_Quiet):
    """androguard's EncodedValue of a static field: `get_value()`/`value` typed
    as androguard has it (int, str, bool, None, lists for field and method
    references); an array or annotation is an object whose repr() is
    androguard's with the address as 0x0."""

    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def get_value(self):
        return self.value


class DCode(_Quiet):
    """androguard's DCode for one method's code: get_instructions() is a
    generator (an invalid method raises InvalidInstruction on the first
    next()), get_instruction(idx, off), off_to_pos(), get_ins_off(),
    get_raw(), get_length()."""

    __slots__ = ("_load",)

    def __init__(self, load):
        # load() -> (instructions, their byte offsets), from a bounded LRU.
        self._load = load

    def get_instructions(self):
        yield from self._load()[0]

    def is_cached_instructions(self) -> bool:
        return True

    def get_instruction(self, idx: int, off=None):
        if off is not None:
            idx = self.off_to_pos(off)
        return self._load()[0][idx]

    def off_to_pos(self, off: int) -> int:
        from bisect import bisect_left

        offs = self._load()[1]
        i = bisect_left(offs, off)
        return i if i < len(offs) and offs[i] == off else -1

    def get_ins_off(self, off: int):
        from bisect import bisect_left

        insns, offs = self._load()
        i = bisect_left(offs, off)
        return insns[i] if i < len(offs) and offs[i] == off else None

    def get_raw(self) -> bytearray:
        buff = bytearray()
        for i in self.get_instructions():
            buff += i.get_raw()
        return buff

    def get_length(self) -> int:
        return len(self.get_raw())


class DalvikCode(_Quiet):
    """androguard's DalvikCode: get_bc(), get_instruction(),
    get_registers_size()."""

    __slots__ = ("_load", "_registers")

    def __init__(self, load, registers):
        self._load = load
        self._registers = registers

    def get_bc(self) -> DCode:
        return DCode(self._load)

    def get_instruction(self, idx: int, off=None):
        return DCode(self._load).get_instruction(idx, off)

    def get_registers_size(self) -> int:
        return self._registers


# Method rows from Apk.dex_class(): (class_name, name, descriptor,
# access_flags, flags string, code_off, has_code, registers_size, method_idx).
_M_CLS, _M_NAME, _M_DESC, _M_FLAGS, _M_FSTR, _M_CODE_OFF, _M_HAS_CODE, _M_REGS, _M_IDX = range(9)
# Field rows: (class_name, name, descriptor, access_flags, flags string,
# init (repr, value) or None, field_idx).
_F_CLS, _F_NAME, _F_DESC, _F_FLAGS, _F_FSTR, _F_INIT, _F_IDX = range(7)


def _information(proto: str, registers) -> dict:
    """EncodedMethod.get_information(), verbatim from androguard 4.1.3, for a
    method whose code has `registers` registers (None: no code)."""
    info = dict()
    if registers is not None:
        nb = registers
        ret = proto.split(')')
        params = ret[0][1:].split()

        info["return"] = get_type(ret[1])

        if params:
            info["registers"] = (0, nb - len(params) - 1)
            j = 0
            info["params"] = []
            for i in range(nb - len(params), nb):
                info["params"].append((i, get_type(params[j])))
                j += 1
        else:
            info["registers"] = (0, nb - 1)

    return info


class EncodedMethod(_Quiet):
    """androguard's EncodedMethod (after load()), for one entry of a
    class_data."""

    __slots__ = ("_vm", "_off", "_pos", "_row")

    def __init__(self, vm: "DEX", class_data_off: int, pos: int, row):
        self._vm = vm
        self._off = class_data_off
        self._pos = pos
        self._row = row

    # identity: the class_data entry
    def _ident(self):
        return (self._vm._ident(), self._off, self._pos)

    def __eq__(self, other):
        return isinstance(other, EncodedMethod) and self._ident() == other._ident()

    def __hash__(self):
        return hash(self._ident())

    # attributes androguard sets on load()
    @property
    def CM(self) -> ClassManager:
        return self._vm.CM

    @property
    def class_name(self) -> str:
        return self._row[_M_CLS]

    @property
    def name(self) -> str:
        return self._row[_M_NAME]

    @property
    def proto(self) -> str:
        return self._row[_M_DESC]

    @property
    def access_flags(self) -> int:
        return self._row[_M_FLAGS]

    @property
    def code_off(self) -> int:
        return self._row[_M_CODE_OFF]

    @property
    def method_idx(self) -> int:
        return self._row[_M_IDX]

    @property
    def code(self):
        return self.get_code()

    @property
    def descriptor(self) -> str:
        return self._row[_M_DESC]

    @property
    def full_name(self) -> str:
        return ' '.join([self.class_name, self.name, self.get_descriptor()])

    def get_class_name(self) -> str:
        return self._row[_M_CLS]

    def get_name(self) -> str:
        return self._row[_M_NAME]

    def get_descriptor(self) -> str:
        return self._row[_M_DESC]

    def get_access_flags(self) -> int:
        return self._row[_M_FLAGS]

    def get_access_flags_string(self) -> str:
        return self._row[_M_FSTR]

    def get_code_off(self) -> int:
        return self._row[_M_CODE_OFF]

    def get_address(self) -> int:
        return self._row[_M_CODE_OFF] + 0x10

    def get_method_idx(self) -> int:
        return self._row[_M_IDX]

    def _load(self):
        return self._vm._insns(self._row[_M_CODE_OFF])

    def get_code(self):
        if not self._row[_M_HAS_CODE]:
            return None
        return DalvikCode(self._load, self._row[_M_REGS])

    def get_instructions(self):
        code = self.get_code()
        if code is None:
            return []
        return code.get_bc().get_instructions()

    def get_instructions_idx(self):
        if self.get_code() is None:
            return
        insns, offs = self._load()
        yield from zip(offs, insns)

    def get_instruction(self, idx: int, off=None):
        code = self.get_code()
        if code is not None:
            return code.get_bc().get_instruction(idx, off)
        return None

    def get_length(self) -> int:
        code = self.get_code()
        if code is not None:
            return code.get_bc().get_length()
        return 0

    def get_locals(self) -> int:
        ret = self.proto.split(')')
        params = ret[0][1:].split()
        code = self.get_code()
        if code is None:
            raise AttributeError("'NoneType' object has no attribute 'get_registers_size'")
        return code.get_registers_size() - len(params) - 1

    def get_information(self) -> dict:
        return _information(self.get_descriptor(), self._row[_M_REGS] if self._row[_M_HAS_CODE] else None)

    def __str__(self):
        return "{}->{}{} [access_flags={}] @ 0x{:x}".format(
            self.get_class_name(),
            self.get_name(),
            self.get_descriptor(),
            self.get_access_flags_string(),
            self.get_code_off(),
        )


class EncodedField(_Quiet):
    """androguard's EncodedField (after load()), for one entry of a
    class_data."""

    __slots__ = ("_vm", "_off", "_pos", "_row")

    def __init__(self, vm: "DEX", class_data_off: int, pos: int, row):
        self._vm = vm
        self._off = class_data_off
        self._pos = pos
        self._row = row

    def _ident(self):
        return (self._vm._ident(), self._off, self._pos, "field")

    def __eq__(self, other):
        return isinstance(other, EncodedField) and self._ident() == other._ident()

    def __hash__(self):
        return hash(self._ident())

    @property
    def CM(self) -> ClassManager:
        return self._vm.CM

    @property
    def class_name(self) -> str:
        return self._row[_F_CLS]

    @property
    def name(self) -> str:
        return self._row[_F_NAME]

    @property
    def proto(self) -> str:
        return self._row[_F_DESC]

    @property
    def access_flags(self) -> int:
        return self._row[_F_FLAGS]

    @property
    def init_value(self):
        return self.get_init_value()

    def get_class_name(self) -> str:
        return self._row[_F_CLS]

    def get_name(self) -> str:
        return self._row[_F_NAME]

    def get_descriptor(self) -> str:
        return self._row[_F_DESC]

    def get_access_flags(self) -> int:
        return self._row[_F_FLAGS]

    def get_access_flags_string(self) -> str:
        return self._row[_F_FSTR]

    def get_field_idx(self) -> int:
        return self._row[_F_IDX]

    def get_init_value(self):
        init = self._row[_F_INIT]
        return None if init is None else EncodedValue(_encoded_value(init[1]))

    def __str__(self):
        return "{}->{} {} [access_flags={}]\n".format(
            self.get_class_name(),
            self.get_name(),
            self.get_descriptor(),
            self.get_access_flags_string(),
        )


class _EncodedObject:
    """An EncodedArray/EncodedAnnotation value: only repr() (and so str()) is
    reproduced, with the address as 0x0."""

    __slots__ = ("_obj",)

    def __init__(self, obj):
        self._obj = obj

    def __repr__(self):
        return repr(self._obj)


def _encoded_value(v):
    return _EncodedObject(v) if isinstance(v, _native.EncodedObject) else v


class ClassDefItem(_Quiet):
    """androguard's ClassDefItem for one class_def of a DEX. The name is
    known up front; the rest (superclass, interfaces, flags, methods, fields)
    is fetched when first asked for."""

    __slots__ = ("_vm", "_ci", "_name")

    def __init__(self, vm: "DEX", ci: int, name: str):
        self._vm = vm
        self._ci = ci
        self._name = name

    def _ident(self):
        return (self._vm._ident(), self._ci)

    def __eq__(self, other):
        return isinstance(other, ClassDefItem) and self._ident() == other._ident()

    def __hash__(self):
        return hash(self._ident())

    def _info(self):
        return self._vm._class(self._ci)

    @property
    def CM(self) -> ClassManager:
        return self._vm.CM

    @property
    def name(self) -> str:
        return self._name

    @property
    def sname(self) -> str:
        return self._info()[0][2]

    @property
    def interfaces(self) -> list:
        return list(self._info()[0][3])

    def get_name(self) -> str:
        return self._name

    def get_superclassname(self) -> str:
        return self._info()[0][2]

    def get_interfaces(self) -> list:
        return list(self._info()[0][3])

    def get_access_flags_string(self) -> str:
        return self._info()[0][1]

    def get_class_data_off(self) -> int:
        return self._info()[0][4]

    def get_methods(self) -> list:
        return list(self._info()[1])

    def get_fields(self) -> list:
        return list(self._info()[2])

    def __str__(self):
        return "{}->{}".format(self.get_superclassname(), self.get_name())

    def __repr__(self):
        return "<dvm.ClassDefItem {}>".format(self.__str__())


class _MethodsView:
    """get_encoded_methods(): every class's get_methods() in order, made as
    it is walked (a shared class_data's methods once per class_def, as in
    androguard). Iterable any number of times; len() and indexing walk it."""

    __slots__ = ("_vm",)

    def __init__(self, vm):
        self._vm = vm

    def __iter__(self):
        for c in self._vm.get_classes():
            yield from c.get_methods()

    def __len__(self):
        return sum(len(c.get_methods()) for c in self._vm.get_classes())

    def __getitem__(self, i):
        return list(self)[i]

    def __add__(self, other):
        return list(self) + list(other)

    def __radd__(self, other):
        return list(other) + list(self)


class DEX(_Quiet):
    """``androguard.core.dex.DEX`` drop-in.

    ``DEX(buff)`` makes androguard 4.1.3's header checks and raises what it
    raises (``ValueError("Not a DEX file, Header too small.")``, ``"This is
    not a DEX file! Wrong endian tag: ..."``, wrong magic, Adler-32
    checksum, header size, id counts; ``NotImplementedError`` for a
    byte-swapped tag), so callers' error handling works unchanged; then checks
    the native reader can parse it (``ValueError`` otherwise). The bytes are
    kept until an ``androguard_rs.analysis.Analysis`` it was added to runs
    ``create_xref()``, which indexes every added DEX together and binds each
    DEX to it. A DEX used on its own indexes itself when first asked.

    ``AnalyzeAPK`` returns one per DEX file, bound to its index."""

    __slots__ = ("_raw", "_rs", "_d", "CM", "api_version", "_classes", "_cache", "_insn_cache", "_analysis",
                 "__weakref__")

    _CLASS_CACHE = 512
    _INSN_CACHE = 256

    def __init__(self, buff, decompiler=None, config=None, using_api=None):
        err = _native._dex_header_error(buff)
        if err is not None:
            raise (NotImplementedError if err[0] == "NotImplementedError" else ValueError)(err[1])
        _native._dex_parse_check(buff)
        self._init(None, None)
        self._raw = buff
        self.api_version = using_api if using_api else 16

    def _init(self, rs, d):
        self._raw = None
        self._rs = rs
        self._d = d
        self.CM = ClassManager(self)
        self.api_version = 16
        self._classes = None
        self._cache = _LRU(self._CLASS_CACHE)
        self._insn_cache = _LRU(self._INSN_CACHE)
        self._analysis = None

    @classmethod
    def _of(cls, rs, d: int, api_version=16) -> "DEX":
        """The DEX object for DEX number `d` of the native index `rs`."""
        self = object.__new__(cls)
        self._init(rs, d)
        self.api_version = api_version
        return self

    def _bind(self, rs, d: int) -> None:
        """Serve this DEX from `rs` (an index over every added DEX), drop the
        bytes and anything cached from a private index."""
        self._rs, self._d, self._raw = rs, d, None
        self._classes = None
        self._cache = _LRU(self._CLASS_CACHE)
        self._insn_cache = _LRU(self._INSN_CACHE)

    def _native(self):
        if self._rs is None:
            self._rs = _native.Apk.from_dex_list([self._raw])
            self._d = 0
        return self._rs

    def _ident(self):
        return id(self)

    def _class(self, ci: int):
        """(header, methods, fields) of class_def `ci`. Members are kept per
        class_data (class_defs sharing one get the same objects, as in
        androguard), headers per class_def, both in bounded LRUs."""
        def make_header():
            name, flags, sup, ifaces, off = self._native().dex_class_header(self._d, ci)
            return (name, flags, sup, tuple(ifaces), off)

        header = self._cache.get(("h", ci), make_header)
        off = header[4]

        def make_members():
            if off == 0:
                return ((), ())
            mrows, frows = self._native().dex_class_members(self._d, ci)
            return (tuple(EncodedMethod(self, off, i, r) for i, r in enumerate(mrows)),
                    tuple(EncodedField(self, off, i, r) for i, r in enumerate(frows)))

        methods, fields = self._cache.get(("m", off), make_members) if off else ((), ())
        return (header, methods, fields)

    def _insns(self, code_off: int):
        def make():
            data = self._native().code_instructions(self._d, code_off)
            if data is None:
                return ([], [])
            return (_instructions(data), [r[0] for r in data[1]])

        return self._insn_cache.get(code_off, make)

    # androguard API
    def set_analysis(self, analysis_dex) -> None:
        self._analysis = analysis_dex

    def set_decompiler(self, decompiler) -> None:
        pass

    def get_api_version(self) -> int:
        return self.api_version

    def get_class_manager(self) -> ClassManager:
        return self.CM

    def get_classes(self) -> list:
        if self._classes is None:
            names = self._native().dex_class_names(self._d)
            self._classes = [ClassDefItem(self, ci, n) for ci, n in enumerate(names)]
        return self._classes

    def get_classes_names(self, update: bool = False) -> list:
        return [c.get_name() for c in self.get_classes()]

    def get_len_classes(self) -> int:
        return len(self.get_classes())

    def get_class(self, name: str):
        for i in self.get_classes():
            if i.get_name() == name:
                return i
        return None

    def get_encoded_methods(self):
        return _MethodsView(self)

    def get_len_encoded_methods(self) -> int:
        return len(self.get_encoded_methods())

    def get_encoded_method(self, name: str) -> list:
        prog = _re.compile(name)
        return [m for m in self.get_encoded_methods() if prog.match(m.name)]

    def get_encoded_method_descriptor(self, class_name: str, method_name: str, descriptor: str):
        key = class_name + method_name + descriptor
        hit = self._native().dex_find_member(self._d, key, False)
        return None if hit is None else self.get_classes()[hit[0]].get_methods()[hit[1]]

    def get_encoded_methods_class_method(self, class_name: str, method_name: str):
        for i in self.get_encoded_methods():
            if i.get_name() == method_name and i.get_class_name() == class_name:
                return i
        return None

    def get_encoded_methods_class(self, class_name: str) -> list:
        return [i for i in self.get_encoded_methods() if class_name == i.get_class_name()]

    def get_encoded_fields(self) -> list:
        return [f for c in self.get_classes() for f in c.get_fields()]

    def get_len_encoded_fields(self) -> int:
        return len(self._native().dex_field_names(self._d))

    def get_encoded_field(self, name: str) -> list:
        prog = _re.compile(name)
        classes = self.get_classes()
        return [classes[ci].get_fields()[pos] for ci, pos, fname in self._native().dex_field_names(self._d)
                if prog.match(fname)]

    def get_encoded_fields_class(self, class_name: str) -> list:
        return [i for i in self.get_encoded_fields() if class_name == i.get_class_name()]

    def get_encoded_field_descriptor(self, class_name: str, field_name: str, descriptor: str):
        key = class_name + field_name + descriptor
        hit = self._native().dex_find_member(self._d, key, True)
        return None if hit is None else self.get_classes()[hit[0]].get_fields()[hit[1]]

    def get_ssl_candidate_methods(self) -> list:
        """Not androguard: the EncodedMethods of get_encoded_methods(), in its
        order, that may implement or weaken TLS certificate/hostname
        validation (a cheap superset for callers that then run their own
        per-method checks: a method named checkServerTrusted, verify or
        onReceivedSslError, or whose code new-instances a type ending in
        ``Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;``, sget-objects
        a field containing ``...SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER``,
        invoke-statics a method ending in ``...->getInsecure(I
        Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;``, or
        can't be read or disassembled)."""
        classes = self.get_classes()
        return [classes[ci].get_methods()[pos] for ci, pos in self._native().ssl_candidates(self._d)]

    def __repr__(self):
        return f"<androguard_rs.dex.DEX #{self._d}>"
