"""androguard-compatible Analysis objects over ``androguard_rs``.

androguard 4.1.3's ``AnalyzeAPK`` returns an ``Analysis`` (``dx``) whose
``ClassAnalysis``, ``MethodAnalysis``, ``EncodedMethod``, ``Instruction``,
field and ``ARSCParser`` objects callers walk. This module provides lazy,
lightweight stand-ins for those objects, with androguard's attributes and
results, backed by ``androguard_rs.Apk`` and ``androguard_rs.Resources``.
It ships as ``androguard_rs._analysis``. Nothing is built for the whole APK
up front, and nothing is kept on the Python side: every object a query
returns is made for it, and only the ``Analysis`` (and the DEX objects) live
on.

- The class list, each class's methods and a table of method names are
  native: a ``find_methods()`` / ``find_classes()`` pattern with a literal
  prefix looks only at the class names that start with it, and a method
  name pattern with one only at the classes having such a method (and at
  only those rows). ``get_class_analysis()`` is a native lookup, and
  ``ClassDefItem`` asks for one class's superclass/interfaces.
- ``get_fields()`` (own fields, then the foreign fields the class's code
  touches) and typed ``init_value.value`` come from ``class_fields()``;
  ``get_code().get_bc().get_instructions()`` are ``androguard_rs.dex``
  Instruction handles.
- ``ClassAnalysis``, ``MethodAnalysis`` and the rest are handles made per
  query that compare (and hash) by what they stand for: two
  ``get_classes()`` walks give equal, not identical, ``ClassAnalysis``
  objects (androguard's are the same objects).
- ``MethodAnalysis`` objects carry one ``class_methods()`` row; xref
  endpoints carry only what ``xref_from()``/``xref_to()`` return and fetch the
  rest of their row when asked.

Anything else raises ``NotImplementedError`` naming the attribute, and every
such hit is counted in ``GAPS`` (callers often swallow exceptions, so the
counter is what makes a gap visible).

``analyze_apk(path)`` returns ``(apk, dexes, dx)`` like
``androguard.misc.AnalyzeAPK``. ``apk`` is ``androguard_rs.apk.APK`` (see
that module); ``analyze_apk(path, native_apk=False)`` gives androguard's real
``APK`` with only ``get_android_resources()`` redirected.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from collections import Counter
from typing import Iterator

import androguard_rs
from androguard_rs import _arscconfig
from androguard_rs import dex as _dex

__all__ = ["analyze_apk", "Analysis", "ARSCParser", "GAPS", "NOTES"]

#: attribute -> number of times something asked for it and got
#: NotImplementedError.
GAPS: Counter = Counter()
#: Informational counters (accesses that behave as androguard does, e.g. an
#: AttributeError on an ExternalMethod, but are worth seeing).
NOTES: Counter = Counter()

def _gap(owner: str, attr: str):
    key = f"{owner}.{attr}"
    GAPS[key] += 1
    raise NotImplementedError(f"androguard_compat: {key} is not implemented")


def _sig(class_name: str, name: str, descriptor: str) -> str:
    return f"{class_name}->{name}{descriptor.replace(' ', '')}"


def _row_key(row, cls: str):
    """A class_methods() row's native key: its signature for a regular
    class; for an irregular one (see androguard_rs.Apk.class_methods), its
    int key, or (class, e) for the class's own method, given as (e,)."""
    if len(row) <= 5 or row[5] is None:
        return row[0]
    return _full_key(row[5], cls)


def _full_key(key, cls: str):
    return (cls, key[0]) if isinstance(key, tuple) else key


#: The attributes androguard 4.1.3's objects have (dir() of each, taken once
#: from an AnalyzeAPK result), by this module's class name. An attribute
#: androguard has that isn't implemented here is a gap (NotImplementedError,
#: counted in GAPS); one androguard doesn't have either is an AttributeError,
#: as androguard raises (callers probing attributes catch it).
_AG_ATTRS = {
    'Analysis': frozenset([
        '_Analysis__created_xrefs', '_Analysis__method_hashes', '_create_xref', '_resolve_method', 'add',
        'classes', 'create_ipython_exports', 'create_xref', 'fields', 'find_classes', 'find_fields',
        'find_methods', 'find_strings', 'get_android_api_usage', 'get_call_graph', 'get_class_analysis',
        'get_classes', 'get_external_classes', 'get_external_methods', 'get_field_analysis', 'get_fields',
        'get_internal_classes', 'get_internal_methods', 'get_method', 'get_method_analysis',
        'get_method_analysis_by_name', 'get_method_by_name', 'get_methods', 'get_permission_usage',
        'get_permissions', 'get_strings', 'get_strings_analysis', 'is_class_present', 'methods', 'strings',
        'vms'
    ]),
    'ClassAnalysis': frozenset([
        '_fields', '_methods', 'add_field', 'add_field_xref_read', 'add_field_xref_write', 'add_method',
        'add_method_xref_from', 'add_method_xref_to', 'add_xref_const_class', 'add_xref_from',
        'add_xref_new_instance', 'add_xref_to', 'apilist', 'extends', 'external', 'get_class',
        'get_field_analysis', 'get_fields', 'get_method_analysis', 'get_methods', 'get_nb_methods',
        'get_vm_class', 'get_xref_const_class', 'get_xref_from', 'get_xref_new_instance', 'get_xref_to',
        'implements', 'is_android_api', 'is_external', 'name', 'orig_class', 'set_domain_flag',
        'set_restriction_flag', 'xrefconstclass', 'xreffrom', 'xrefnewinstance', 'xrefto'
    ]),
    'MethodAnalysis': frozenset([
        '_MethodAnalysis__vm', '_create_basic_block', 'access', 'add_xref_const_class', 'add_xref_from',
        'add_xref_new_instance', 'add_xref_read', 'add_xref_to', 'add_xref_write', 'apilist',
        'basic_blocks', 'class_name', 'code', 'descriptor', 'domain_flag', 'exceptions', 'full_name',
        'get_access_flags_string', 'get_basic_blocks', 'get_class_name', 'get_descriptor', 'get_length',
        'get_method', 'get_vm', 'get_xref_const_class', 'get_xref_from', 'get_xref_new_instance',
        'get_xref_read', 'get_xref_to', 'get_xref_write', 'is_android_api', 'is_external', 'method', 'name',
        'restriction_flag', 'show', 'show_xrefs', 'xrefconstclass', 'xreffrom', 'xrefnewinstance',
        'xrefread', 'xrefto', 'xrefwrite'
    ]),
    'EncodedMethod': frozenset([
        'CM', 'access_flags', 'access_flags_string', 'add_inote', 'add_note', 'adjust_idx', 'class_name',
        'code', 'code_off', 'descriptor', 'each_params_by_register', 'full_name', 'get_access_flags',
        'get_access_flags_string', 'get_address', 'get_class_name', 'get_code', 'get_code_off', 'get_debug',
        'get_descriptor', 'get_information', 'get_instruction', 'get_instructions', 'get_instructions_idx',
        'get_length', 'get_locals', 'get_method_idx', 'get_method_idx_diff', 'get_name', 'get_raw',
        'get_short_string', 'get_size', 'get_source', 'get_triple', 'is_cached_instructions', 'load',
        'loaded', 'method_idx', 'method_idx_diff', 'name', 'notes', 'offset', 'proto', 'reload',
        'set_code_idx', 'set_instructions', 'set_name', 'show', 'show_info', 'show_notes', 'source'
    ]),
    '_Code': frozenset([
        'CM', '_begin_show', '_end_show', 'add_inote', 'code', 'debug_info_off', 'get_bc', 'get_debug',
        'get_debug_info_off', 'get_handlers', 'get_ins_size', 'get_insns_size', 'get_instruction',
        'get_length', 'get_obj', 'get_off', 'get_outs_size', 'get_raw', 'get_registers_size', 'get_size',
        'get_tries', 'get_tries_size', 'handlers', 'ins_size', 'insns_size', 'offset', 'outs_size',
        'registers_size', 'seek', 'set_off', 'show', 'tries', 'tries_size'
    ]),
    '_DCode': frozenset([
        'CM', 'add_inote', 'cached_instructions', 'get_ins_off', 'get_insn', 'get_instruction',
        'get_instructions', 'get_length', 'get_raw', 'idx', 'insn', 'is_cached_instructions', 'notes',
        'off_to_pos', 'offset', 'seek', 'set_insn', 'set_instructions', 'show', 'size'
    ]),
    'ClassDefItem': frozenset([
        'CM', '_get_annotation_type_ids', 'access_flags', 'access_flags_string',
        'annotations_directory_item', 'annotations_off', 'class_data_item', 'class_data_off', 'class_idx',
        'get_access_flags', 'get_access_flags_string', 'get_annotations', 'get_annotations_off', 'get_ast',
        'get_class_data', 'get_class_data_off', 'get_class_idx', 'get_fields', 'get_interfaces',
        'get_interfaces_off', 'get_length', 'get_methods', 'get_name', 'get_obj', 'get_raw', 'get_source',
        'get_source_ext', 'get_source_file_idx', 'get_static_values_off', 'get_superclass_idx',
        'get_superclassname', 'interfaces', 'interfaces_off', 'name', 'offset', 'reload', 'set_name',
        'show', 'sname', 'source', 'source_file_idx', 'static_values', 'static_values_off', 'superclass_idx'
    ]),
    'ExternalClass': frozenset([
        'add_method', 'get_methods', 'get_name', 'methods', 'name'
    ]),
    'FieldAnalysis': frozenset([
        'add_xref_read', 'add_xref_write', 'field', 'get_field', 'get_xref_read', 'get_xref_write', 'name',
        'xrefread', 'xrefwrite'
    ]),
    'EncodedField': frozenset([
        'CM', 'access_flags', 'access_flags_string', 'adjust_idx', 'class_name', 'field_idx',
        'field_idx_diff', 'get_access_flags', 'get_access_flags_string', 'get_class_name', 'get_descriptor',
        'get_field_idx', 'get_field_idx_diff', 'get_init_value', 'get_name', 'get_obj', 'get_raw',
        'get_size', 'init_value', 'load', 'loaded', 'name', 'offset', 'proto', 'reload', 'set_init_value',
        'set_name', 'show'
    ]),
    '_InitValue': frozenset([
        'CM', '_getintvalue', 'get_length', 'get_obj', 'get_raw', 'get_value', 'get_value_arg',
        'get_value_type', 'raw_value', 'show', 'val', 'value', 'value_arg', 'value_type'
    ]),
}
#: androguard's class name, for the AttributeError message.
_AG_NAMES = {"_Code": "DalvikCode", "_DCode": "DCode", "_InitValue": "EncodedValue"}


class _Loud:
    """Base: unknown attributes raise NotImplementedError and are counted,
    unless androguard's object lacks them too (AttributeError, noted)."""

    __slots__ = ()

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        name = type(self).__name__
        known = _AG_ATTRS.get(name)
        if known is not None and attr not in known:
            NOTES[f"{name}.{attr} (AttributeError, as androguard)"] += 1
            raise AttributeError(f"'{_AG_NAMES.get(name, name)}' object has no attribute '{attr}'")
        _gap(name, attr)


# ── Instructions ──────────────────────────────────────────────────────────────
#
# Instruction objects are androguard_rs.dex's classes (Instruction11n,
# Instruction35c, PackedSwitch, ...), built per method from one native call
# and kept by the DEX object: get_instructions() returns the same objects
# every time, as androguard's cached list does.
#
# androguard_rs models androguard after AnalyzeAPK/create_xref(), which has
# disassembled (and cached) every method: get_instruction(idx) works without
# iterating first. (Without create_xref, androguard's DCode.get_instruction(idx)
# raises TypeError until something iterates; with it, a method androguard
# can't disassemble fails the whole analysis. Here such a method raises
# InvalidInstruction when its instructions are asked for.)


class _Code(_Loud):
    """androguard's DalvikCode: truthy, get_bc() for its instructions."""

    __slots__ = ("_ma",)

    def __init__(self, ma: "MethodAnalysis"):
        self._ma = ma

    def __eq__(self, other):
        return isinstance(other, _Code) and self._ma == other._ma

    def __hash__(self):
        return hash(("_Code", self._ma))

    def get_bc(self) -> "_DCode":
        return _DCode(self._ma)

    def get_instruction(self, idx: int, off=None):
        return _DCode(self._ma).get_instruction(idx, off)


class _DCode(_Loud):
    """androguard's DCode. get_instructions() is a generator: the method is
    disassembled on the first next() (an invalid one raises
    InvalidInstruction there, as androguard's does)."""

    __slots__ = ("_ma",)

    def __init__(self, ma: "MethodAnalysis"):
        self._ma = ma

    def __eq__(self, other):
        return isinstance(other, _DCode) and self._ma == other._ma

    def __hash__(self):
        return hash(("_DCode", self._ma))

    def _all(self):
        return self._ma._dx._insns(self._ma._key)

    def get_instructions(self) -> Iterator:
        yield from self._all()

    def is_cached_instructions(self) -> bool:
        return True

    def get_instruction(self, idx: int, off=None):
        """The instruction at list position `idx`, or, if `off` is given, the
        one starting at byte offset `off`: as androguard's, an offset that
        isn't an instruction boundary gives position -1 (the last
        instruction), and a position out of range raises IndexError."""
        if off is not None:
            idx = self.off_to_pos(off)
        loc = self._ma._dx._code_loc(self._ma._key)
        if loc is not None and type(idx) is int and -(1 << 62) < idx < (1 << 62):
            rs, d, code_off = loc
            return rs._insn_at(d, code_off, idx, _dex._Insns, _dex._CLASSES)
        return _dex._at(self._all(), idx)

    def off_to_pos(self, off: int) -> int:
        loc = self._ma._dx._code_loc(self._ma._key)
        if loc is not None and type(off) is int:
            rs, d, code_off = loc
            return rs._insn_pos(d, code_off, off)[1]
        offs = [i._row for i in self._all()]
        i = bisect_left(offs, off)
        return i if i < len(offs) and offs[i] == off else -1

    def get_ins_off(self, off: int):
        insns = self._all()
        offs = [i._row for i in insns]
        i = bisect_left(offs, off)
        return insns[i] if i < len(offs) and offs[i] == off else None

    def get_raw(self) -> bytearray:
        buff = bytearray()
        for i in self.get_instructions():
            buff += i.get_raw()
        return buff

    def get_length(self) -> int:
        return len(self.get_raw())


# ── Methods ───────────────────────────────────────────────────────────────────


def _from_dex_method(slot: str) -> property:
    return property(lambda self: getattr(self._dex_method(), slot))


class EncodedMethod(_Loud, _dex.EncodedMethod):
    """A MethodAnalysis's EncodedMethod. Name, descriptor, flags and code come
    from its class_methods() row and native key; the rest (code_off,
    registers, get_information(), str(), CM, equality) from the DEX-level
    EncodedMethod handle it is (androguard_rs.dex.EncodedMethod), found on
    first use."""

    __slots__ = ("_ma", "_dexm")

    # The DEX-level handle's keys, read from it.
    _core = _from_dex_method("_core")
    _rs = _from_dex_method("_rs")
    _d = _from_dex_method("_d")
    _off = _from_dex_method("_off")
    _pos = _from_dex_method("_pos")
    _idx = _from_dex_method("_idx")
    _flags = _from_dex_method("_flags")
    _code_off = _from_dex_method("_code_off")

    def __init__(self, ma: "MethodAnalysis"):
        self._ma = ma
        self._dexm = None

    def _dex_method(self) -> "_dex.EncodedMethod":
        if self._dexm is None:
            ma = self._ma
            loc = ma._dx._rs.method_location(ma._cls, ma._key)
            if loc is None:
                _gap("EncodedMethod", f"<location of {ma._sig}>")
            d, ci, _off, pos = loc
            self._dexm = ma._dx._vm_views()[d]._method(ci, pos)
        return self._dexm

    def _ident(self):
        return self._dex_method()._ident()

    __eq__ = _dex.EncodedMethod.__eq__
    __hash__ = _dex.EncodedMethod.__hash__

    @property
    def _vm(self):
        return self._dex_method()._vm

    @property
    def class_name(self) -> str:
        return self._ma._mcls

    @property
    def proto(self) -> str:
        return self._ma._desc

    @property
    def descriptor(self) -> str:
        return self._ma._desc

    def get_information(self) -> dict:
        return self._dex_method().get_information()

    def __str__(self):
        return self._dex_method().__str__()

    @property
    def name(self) -> str:
        return self._ma._name

    def get_name(self) -> str:
        return self._ma._name

    def get_descriptor(self) -> str:
        return self._ma._desc

    def get_class_name(self) -> str:
        return self._ma._mcls

    def get_access_flags_string(self) -> str:
        return self._ma._row()[3]

    def get_code(self):
        return _Code(self._ma) if self._ma._dx._rs.has_code(self._ma._key) else None

    def _has_code(self) -> bool:
        return self._ma._dx._rs.has_code(self._ma._key)

    def get_length(self) -> int:
        code = self.get_code()
        return 0 if code is None else code.get_bc().get_length()

    def get_instructions_idx(self) -> Iterator:
        # androguard: a generator; no code -> nothing, otherwise every
        # instruction with its byte offset (the running sum of get_length()).
        # An invalid method raises InvalidInstruction on the first next().
        if self.get_code() is None:
            return
        for i in self._ma._dx._insns(self._ma._key):
            yield (i._row, i)

    def get_instructions(self):
        # androguard: [] without code, else DCode.get_instructions() (a generator).
        code = self.get_code()
        if code is None:
            return []
        return code.get_bc().get_instructions()

    def get_instruction(self, idx: int, off=None):
        # androguard: None without code.
        code = self.get_code()
        if code is not None:
            return code.get_bc().get_instruction(idx, off)
        return None


class ExternalMethod:
    """androguard's ExternalMethod: name/descriptor/class only. Anything else
    is an AttributeError, as in androguard (e.g. `get_code()`), and is
    noted in NOTES."""

    __slots__ = ("class_name", "name", "descriptor")

    def __init__(self, class_name: str, name: str, descriptor: str):
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor

    def get_name(self) -> str:
        return self.name

    def get_class_name(self) -> str:
        return self.class_name

    def get_descriptor(self) -> str:
        return self.descriptor

    def get_access_flags_string(self) -> str:
        return ""

    @property
    def full_name(self) -> str:
        return self.class_name + " " + self.name + " " + str(self.descriptor)

    def __str__(self):
        return f"{self.class_name}->{self.name}{self.descriptor}"

    def __repr__(self):
        return f"<analysis.ExternalMethod {self}>"

    # One object per (class, name, descriptor) in androguard.
    def __eq__(self, other):
        return isinstance(other, ExternalMethod) and (self.class_name, self.name, self.descriptor) == (
            other.class_name, other.name, other.descriptor)

    def __hash__(self):
        return hash((self.class_name, self.name, self.descriptor))

    def __getattr__(self, attr):
        if not (attr.startswith("__") and attr.endswith("__")):
            NOTES[f"ExternalMethod.{attr} (AttributeError, as androguard)"] += 1
        raise AttributeError(f"'ExternalMethod' object has no attribute '{attr}'")


class MethodAnalysis(_Loud):
    """One method. Built either from a full class_methods() row or, for an
    xref endpoint, from (class, sig, name, descriptor, key); the rest of the
    row (flags, external) is fetched from the class when first needed.

    `_key` is what the native queries take for it: the signature (which
    names the definition calls resolve to, i.e. the last one), or, for an
    earlier definition's method that a later definition of its class
    overrides, the int key its row carries."""

    __slots__ = ("_dx", "_cls", "_sig", "_name", "_desc", "_full", "_key", "_mcls")

    def __init__(self, dx: "Analysis", cls: str, sig: str, name: str, desc: str, full=None, key=None, mcls=None):
        self._dx = dx
        self._cls = cls
        self._sig = sig
        self._name = name
        self._desc = desc
        self._full = full
        self._key = sig if key is None else key
        # get_class_name(): its method_id's class, which a crafted class_data
        # can make differ from the class listing it.
        self._mcls = cls if mcls is None else mcls

    def _row(self):
        if self._full is None:
            if isinstance(self._key, str):
                row = self._dx._method_row(self._cls, self._key)
            else:
                row = self._dx._rs.method_row(self._key)
            if row is None:
                _gap("MethodAnalysis", f"<row of {self._sig}>")
            self._full = row
        return self._full

    @property
    def name(self) -> str:
        return self._name

    @property
    def descriptor(self) -> str:
        return self._desc

    @property
    def class_name(self) -> str:
        return self._mcls

    def is_external(self) -> bool:
        return self._row()[4]

    def get_method(self):
        if self.is_external():
            return ExternalMethod(self._cls, self._name, self._desc)
        return EncodedMethod(self)

    @property
    def method(self):
        return self.get_method()

    @property
    def access(self) -> str:
        return self.get_method().get_access_flags_string()

    @property
    def full_name(self) -> str:
        return self.get_method().full_name

    def get_class_name(self) -> str:
        return self.class_name

    def get_access_flags_string(self) -> str:
        return self.access

    def get_descriptor(self) -> str:
        return self._desc

    # androguard has one MethodAnalysis per method, compared by identity; here
    # objects are made per call, so they compare by the method they stand for.
    def __eq__(self, other):
        return isinstance(other, MethodAnalysis) and other._dx is self._dx and other._key == self._key

    def __hash__(self):
        return hash((id(self._dx), self._key))

    def _xrefs(self, rows):
        dx = self._dx
        out = []
        for row in rows:
            sig, cls, name, desc, off = row[:5]
            key, mcls = (row[5], row[6]) if len(row) > 5 else (None, None)
            out.append((dx.get_class_analysis(cls), MethodAnalysis(dx, cls, sig, name, desc, key=key, mcls=mcls), off))
        return out

    def get_xref_from(self):
        # androguard returns a set, iterated in hash-by-id (memory address)
        # order, i.e. arbitrary and different from run to run; this is a set
        # too, iterated in the index's edge order (one of those orders, the
        # same every run).
        return _XrefSet(self._xrefs(self._dx._rs.xref_from(self._key)))

    def get_xref_to(self):
        return _XrefSet(self._xrefs(self._dx._rs.xref_to(self._key)))

    def __repr__(self):
        return "<analysis.MethodAnalysis {}>".format(self.method)


class _XrefSet(set):
    """get_xref_from()/get_xref_to(): a set of (ClassAnalysis, MethodAnalysis,
    offset), as androguard returns, that iterates (for, list(), next(iter()))
    in a fixed order, the index's. Set operations give plain sets."""

    __slots__ = ("_order",)

    def __init__(self, items=()):
        items = list(items)
        super().__init__(items)
        seen = set()
        self._order = [x for x in items if not (x in seen or seen.add(x))]

    def __iter__(self):
        if len(self._order) != len(self):  # mutated: fall back to set order
            return super().__iter__()
        return iter(self._order)


# ── Fields ────────────────────────────────────────────────────────────────────


class _EncodedObject(_Loud):
    """An EncodedArray/EncodedAnnotation static value: only repr() is
    reproduced (with the address blanked to 0x0)."""

    __slots__ = ("_obj",)

    def __init__(self, obj):
        self._obj = obj

    def __repr__(self):
        return repr(self._obj)


class _InitValue(_Loud):
    """androguard's EncodedValue: `.value` is typed as androguard types it
    (int, str, bool, None, nested lists for field/method references)."""

    __slots__ = ("value",)

    def __init__(self, value):
        self.value = _EncodedObject(value) if isinstance(value, androguard_rs.EncodedObject) else value

    def get_value(self):
        return self.value


class EncodedField(_Loud):
    __slots__ = ("_cls", "_flags", "name", "_type", "init_value")

    def __init__(self, cls: str, flags: str, name: str, ty: str, init):
        self._cls = cls
        self._flags = flags
        self.name = name
        self._type = ty
        # init: None, or (repr text, typed value) from class_fields().
        self.init_value = None if init is None else _InitValue(init[1])

    def get_name(self) -> str:
        return self.name

    def get_class_name(self) -> str:
        return self._cls

    def get_descriptor(self) -> str:
        return self._type

    def get_access_flags_string(self) -> str:
        return self._flags

    def get_init_value(self):
        return self.init_value

    @property
    def class_name(self) -> str:
        return self._cls

    @property
    def proto(self) -> str:
        return self._type

    def __str__(self):
        return "{}->{} {} [access_flags={}]\n".format(self._cls, self.name, self._type, self._flags)


class FieldAnalysis(_Loud):
    __slots__ = ("_field",)

    def __init__(self, field: EncodedField):
        self._field = field

    @property
    def name(self) -> str:
        return self._field.name

    def get_field(self) -> EncodedField:
        return self._field

    @property
    def field(self) -> EncodedField:
        return self._field

    def __repr__(self):
        return "<analysis.FieldAnalysis {}->{}>".format(self._field.class_name, self._field.name)


# ── Classes ───────────────────────────────────────────────────────────────────


class ClassDefItem(_Loud):
    """ClassAnalysis.get_vm_class() of a defined class: the class_def
    androguard holds for it (the last loaded). Name, superclass and
    interfaces are one native lookup; methods, fields, flags, str() and
    equality come from the DEX-level ClassDefItem (androguard_rs.dex)."""

    __slots__ = ("_ca", "_dexc")

    def __init__(self, ca: "ClassAnalysis"):
        self._ca = ca
        self._dexc = None

    def _dex_class(self) -> "_dex.ClassDefItem":
        if self._dexc is None:
            dx = self._ca._dx
            d, ci = dx._rs.class_def_position(self._ca.name)
            self._dexc = dx._vm_views()[d]._class(ci)
        return self._dexc

    def __eq__(self, other):
        if isinstance(other, ClassDefItem):
            other = other._dex_class()
        return self._dex_class() == other

    def __hash__(self):
        return hash(self._dex_class())

    @property
    def name(self) -> str:
        return self._ca.name

    def get_name(self) -> str:
        return self._ca.name

    def get_superclassname(self) -> str:
        return self._ca._dx._rs.class_hierarchy(self._ca.name)[0]

    def get_interfaces(self):
        return self._ca._dx._rs.class_hierarchy(self._ca.name)[1]

    def get_access_flags_string(self) -> str:
        return self._dex_class().get_access_flags_string()

    def get_methods(self) -> list:
        return self._dex_class().get_methods()

    def get_fields(self) -> list:
        return self._dex_class().get_fields()

    def __str__(self):
        return "{}->{}".format(self.get_superclassname(), self.get_name())

    def __repr__(self):
        return "<dvm.ClassDefItem {}>".format(self.__str__())


class ExternalClass(_Loud):
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name

    # one per class in androguard
    def __eq__(self, other):
        return isinstance(other, ExternalClass) and self.name == other.name

    def __hash__(self):
        return hash(("ExternalClass", self.name))

    def get_name(self) -> str:
        return self.name

    def __repr__(self):
        return "<analysis.ExternalClass {}>".format(self.name)


class ClassAnalysis(_Loud):
    """A handle on one class of dx.get_classes(): made per query, equal
    (and hashing equal) to every other for the same class of the same
    Analysis (androguard has one object per class)."""

    __slots__ = ("_dx", "name", "_external")

    def __init__(self, dx: "Analysis", name: str, external: bool):
        self._dx = dx
        self.name = name
        self._external = external

    def __eq__(self, other):
        return isinstance(other, ClassAnalysis) and other._dx is self._dx and other.name == self.name

    def __hash__(self):
        return hash((id(self._dx), self.name))

    def is_external(self) -> bool:
        return self._external

    def _method_rows(self):
        return self._dx._rs.class_methods(self.name) or []

    def _row_of(self, key):
        """The row of a method by its native key (see _row_key; (e,) as
        search_instruction_text(keys=True) gives it is completed here)."""
        return self._dx._rs._class_method_row(self.name, key)

    def get_methods(self):
        # For an irregular class (defined more than once, sharing its
        # class_data, ...), androguard lists after its own methods those
        # create_xref() adds, each with its own code and xrefs; the rows
        # carry the key to ask for them.
        dx = self._dx
        name = self.name
        return [MethodAnalysis(dx, name, r[0], r[1], r[2], r, _row_key(r, name), r[6] if len(r) > 6 else None)
                for r in self._method_rows()]

    def get_class(self):
        return ExternalClass(self.name) if self._external else ClassDefItem(self)

    get_vm_class = get_class

    def get_fields(self):
        # Own fields, then the other classes' fields this class's code reads
        # or writes, in androguard's order (androguard_rs.Apk.class_fields).
        # External classes get none.
        rows = self._dx._rs.class_fields(self.name) or []
        return [FieldAnalysis(EncodedField(*r)) for r in rows]

    def __repr__(self):
        return "<analysis.ClassAnalysis {}{}>".format(self.name, " EXTERNAL" if self._external else "")


_RE_CACHE: dict = {}
_RE_CACHE_MAX = 65536


def _compiled(pattern: str):
    """re.compile(pattern), kept per pattern string (re's own cache holds
    only the last 512 patterns, fewer than a walk over a permission map's
    signatures uses, so each of those would be compiled again per call)."""
    p = _RE_CACHE.get(pattern)
    if p is None:
        p = re.compile(pattern)
        if len(_RE_CACHE) >= _RE_CACHE_MAX:
            _RE_CACHE.clear()
            _PREFIX_CACHE.clear()
        _RE_CACHE[pattern] = p
    return p


def _matcher(pattern):
    """`lambda s: re.match(pattern, s)`, compiled once."""
    if isinstance(pattern, str):
        return _compiled(pattern).match
    return lambda s: re.match(pattern, s)


_PREFIX_CACHE: dict = {}


def _literal_prefix(pattern: str) -> str:
    """The literal characters every re.match() of `pattern` starts with
    ("" if none, or if a flag makes matching case-insensitive)."""
    p = _PREFIX_CACHE.get(pattern)
    if p is None:
        p = _PREFIX_CACHE[pattern] = _parse_prefix(pattern)
    return p


def _parse_prefix(pattern: str) -> str:
    try:
        from re import _parser as sre_parse, _constants as sre_c
    except ImportError:  # Python < 3.11
        import sre_parse
        import sre_constants as sre_c
    compiled = _compiled(pattern)
    if compiled.flags & (re.IGNORECASE | re.LOCALE):
        return ""
    out = []
    for op, av in sre_parse.parse(pattern, compiled.flags):
        if op is not sre_c.LITERAL:
            break
        out.append(chr(av))
    return "".join(out)


class _ClassesView:
    """dx.get_classes(): iterates the class list (natively, a slice at a
    time), handing out a ClassAnalysis per class."""

    __slots__ = ("_dx",)

    def __init__(self, dx):
        self._dx = dx

    def __iter__(self):
        dx = self._dx
        rs = dx._rs
        n = rs.class_count()
        for start in range(0, n, 4096):
            for name, ext in rs.classes_slice(start, start + 4096):
                yield ClassAnalysis(dx, name, ext)

    def __len__(self):
        return self._dx._rs.class_count()


class Analysis(_Loud):
    __slots__ = ("_rs", "_apk", "_views")

    def __init__(self, rs: "androguard_rs.Apk", apk=None):
        self._rs = rs
        self._apk = apk
        self._views = None

    def _vm_views(self) -> list:
        """One androguard_rs.dex.DEX per DEX file of the index, made once
        (they hold nothing until asked)."""
        if self._views is None:
            rs = self._rs  # may build the index (and set _views) first
            if self._views is None:
                self._views = [_dex.DEX._of(rs, d) for d in range(rs.dex_count())]
        return self._views

    @property
    def vms(self) -> list:
        return self._vm_views()

    # internal helpers
    def _class(self, name: str, external: bool) -> ClassAnalysis:
        return ClassAnalysis(self, name, external)

    def _method_row(self, cls: str, key):
        return self._rs._class_method_row(cls, key) if isinstance(cls, str) else None

    def _code_loc(self, key):
        """(native index, DEX number, code_off) of a method's code by its
        native key (signature or row key), or None."""
        rs = self._rs
        loc = rs._code_location(key)
        return None if loc is None else (rs, loc[0], loc[1])

    def _insns(self, key):
        """The Instruction handles (a tuple) of a method with code, by its
        native key (signature or row key); () without code."""
        loc = self._code_loc(key)
        if loc is None:
            return ()
        return self._vm_views()[loc[1]]._insns(loc[2])

    # androguard API
    def get_classes(self):
        return _ClassesView(self)

    def get_class_analysis(self, class_name: str):
        if not isinstance(class_name, str):
            return None
        entry = self._rs.class_entry(class_name)
        if entry is None:
            return None
        return ClassAnalysis(self, class_name, entry[1])

    def _matching_classes(self, pattern):
        """[(position, name, is_external)], in dx.get_classes() order, of the
        classes whose name re.match()es `pattern`, as androguard's loop over
        every class finds them. A str pattern's literal prefix (the leading
        literal characters Python's re parser finds, when no flag makes them
        case-insensitive) is a prefix every match starts with, so only the
        names starting with it are tried."""
        rs = self._rs
        if not rs.class_count():
            return []
        if not isinstance(pattern, str):
            return [(i, n, e) for i, n, e in rs._classes_prefix("") if re.match(pattern, n)]
        match = _compiled(pattern).match
        return [t for t in rs._classes_prefix(_literal_prefix(pattern)) if match(t[1])]

    def find_classes(self, name: str = ".*", no_external: bool = False):
        # androguard 4.1.3: every class, in dx.classes order, whose name
        # re.match()es `name`.
        for _i, cname, ext in self._matching_classes(name):
            if no_external and ext:
                continue
            yield ClassAnalysis(self, cname, ext)

    def find_methods(self, classname: str = ".*", methodname: str = ".*", descriptor: str = ".*",
                     accessflags: str = ".*", no_external: bool = False):
        # androguard 4.1.3: for every class (external ones too), in
        # dx.classes order, whose name re.match()es `classname`, each of its
        # get_methods() whose method's get_name(), get_descriptor() and
        # get_access_flags_string() ("" for an ExternalMethod, which
        # no_external leaves out) re.match() the other three. The patterns
        # are used with Python's re as given (callers pass unescaped
        # class names, lookaheads, space-separated descriptors). Matching
        # runs on the class_methods() rows (natively narrowed to the names
        # with the method pattern's literal prefix); a MethodAnalysis is
        # made only for a match.
        classes = self._method_candidates(classname, methodname)
        if classes is None:
            classes = self._matching_classes(classname)
        # Each pattern is compiled at the first re.match() androguard makes
        # with it (`and` short-circuits), so a bad one raises at the same
        # point.
        yield from self._find_in(classes, methodname, descriptor, accessflags, no_external)

    def _method_candidates(self, classname, methodname):
        """For find_methods(): [(position, name, is_external)], ascending,
        of the classes whose name re.match()es `classname` and that have a
        method whose name starts with `methodname`'s literal prefix (no
        other class can yield a match), or None to look at every class
        matching `classname`. Patterns that don't compile are left to the
        plain loop, which raises where androguard's does."""
        if not (isinstance(methodname, str) and isinstance(classname, str)):
            return None
        try:
            prefix = _literal_prefix(methodname)
            match = _compiled(classname).match
        except re.error:
            return None
        if not prefix:
            return None
        try:
            cands = self._rs._classes_with_method_prefix(prefix)
        except UnicodeError:
            return None
        cprefix = _literal_prefix(classname)
        return [t for t in self._rs._classes_at(cands) if t[1].startswith(cprefix) and match(t[1])]

    def _find_in(self, classes, methodname, descriptor, accessflags, no_external):
        mm = dm = am = None
        prefix = None
        if isinstance(methodname, str):
            try:
                prefix = _literal_prefix(methodname) or None
            except re.error:
                prefix = None
        rs = self._rs
        for _i, cname, _ext in classes:
            try:
                rows = rs.class_methods(cname, prefix)
            except UnicodeError:
                rows = rs.class_methods(cname)
            for r in rows or ():
                external = r[4]
                if no_external and external:
                    continue
                if mm is None:
                    mm = _matcher(methodname)
                if not mm(r[1]):
                    continue
                if dm is None:
                    dm = _matcher(descriptor)
                if not dm(r[2]):
                    continue
                if am is None:
                    am = _matcher(accessflags)
                if am("" if external else r[3]):
                    yield MethodAnalysis(self, cname, r[0], r[1], r[2], r, _row_key(r, cname),
                                         r[6] if len(r) > 6 else None)

    # androguard_rs extensions (not androguard API): whole-APK queries served
    # natively, for callers that would otherwise walk every instruction.
    def const_strings(self, include_jumbo: bool = False):
        """[(class name, [(method name, descriptor, [get_output() of each
        const-string, in order]), ...]), ...] for the internal classes, in
        get_classes() / get_methods() order, methods without one left out.
        See androguard_rs.Apk.const_strings."""
        return self._rs.const_strings(include_jumbo)

    def search_instruction_text(self, needles):
        """(ClassAnalysis, MethodAnalysis) of each internal class's method,
        in get_classes() / get_methods() order, one of whose instructions'
        get_output().lower() contains one of `needles` (matched as given:
        pass them lower-cased). Same result as walking every method's
        get_instructions_idx(), without decoding anything into Python."""
        for sig, key, cls in self._rs.search_instruction_text(list(needles), keys=True):
            ca = self.get_class_analysis(cls)
            row = ca._row_of(sig if key is None else key)
            yield ca, MethodAnalysis(self, cls, sig, row[1], row[2], row, _row_key(row, ca.name),
                                     row[6] if len(row) > 6 else None)


# ── Resources ─────────────────────────────────────────────────────────────────


class ARSCParser(_Loud):
    """androguard's ARSCParser query methods, served by
    androguard_rs.Resources (same results and exceptions)."""

    __slots__ = ("_r",)

    def __init__(self, raw: bytes):
        self._r = androguard_rs.Resources(raw)

    def get_packages_names(self):
        return self._r.get_packages_names()

    def get_public_resources(self, package_name, locale="\x00\x00"):
        return self._r.get_public_resources(package_name, locale)

    def get_resolved_strings(self):
        return self._r.get_resolved_strings()

    def get_resolved_res_configs(self, rid, config=None):
        if config is not None:
            _gap("ARSCParser", "get_resolved_res_configs(config=...)")
        return self._r.get_resolved_res_configs(rid, _arscconfig.from_bytes)

    def get_resource_xml_name(self, r_id, package=None):
        return self._r.get_resource_xml_name(r_id, package)


def _rs_get_android_resources(self):
    """Replacement for APK.get_android_resources(), same caching and None."""
    try:
        return self.arsc["resources.arsc"]
    except KeyError:
        if "resources.arsc" not in self.zip.namelist():
            return None
        self.arsc["resources.arsc"] = ARSCParser(self.zip.read("resources.arsc"))
        return self.arsc["resources.arsc"]


# ── Entry point ───────────────────────────────────────────────────────────────


def analyze_apk(path: str, native_apk: bool = True, tolerant: bool = False):
    """Drop-in for androguard.misc.AnalyzeAPK(path): (apk, dexes, dx).

    `apk` is `androguard_rs.apk.APK`: manifest, files, signing and resources
    read natively, androguard not needed (its `get_androguard_apk()` builds
    androguard's own APK on demand). With `native_apk=False` it is
    androguard's APK instead, with get_android_resources() returning the
    Rust-backed ARSCParser. `dx` is the lazy Analysis facade over
    androguard_rs.Apk(path). `dexes` is one androguard_rs.dex.DEX per DEX file.
    (`androguard_rs.misc.AnalyzeAPK` is the same, with androguard's
    signature, and also takes bytes.)

    Loading fails as androguard's AnalyzeAPK does (a DEX file its `DEX()`
    rejects, a method it can't disassemble; see androguard_rs.misc);
    `tolerant=True` loads such an APK anyway.
    """
    from androguard_rs.misc import load_index

    if native_apk:
        from androguard_rs.apk import APK as NativeAPK

        apk = NativeAPK(path)
        dx = Analysis(load_index(path, tolerant=tolerant), apk)
        return apk, dx._vm_views(), dx

    from androguard.core.apk import APK

    apk = APK(path)
    apk.get_android_resources = _rs_get_android_resources.__get__(apk, APK)
    dx = Analysis(load_index(path, tolerant=tolerant), apk)
    return apk, dx._vm_views(), dx
