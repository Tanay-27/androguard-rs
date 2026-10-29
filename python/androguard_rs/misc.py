"""``androguard.misc.AnalyzeAPK`` drop-in.

``AnalyzeAPK(path)`` / ``AnalyzeAPK(data, raw=True)`` returns ``(a, d, dx)``
like androguard 4.1.3: ``a`` is ``androguard_rs.apk.APK``, ``d`` the list of
``androguard_rs.dex.DEX`` objects (one per DEX file, in load order, served
lazily from the index) and ``dx`` the lazy ``Analysis`` facade over
``androguard_rs.Apk`` (``androguard_rs._analysis``). Sessions aren't
supported.

Loading fails as androguard's does: a DEX file androguard's ``DEX()`` header
checks reject raises its ``ValueError``/``NotImplementedError``, and a method
it can't disassemble raises its ``InvalidInstruction`` (``Analysis.add()``
doesn't catch it), whichever androguard meets first. ``tolerant=True`` (not
androguard) loads such an APK anyway: only the "Header too small" and
"Wrong endian tag" checks are made (failing the load, as before), and a
method that can't be disassembled raises only when its instructions are
asked for.
"""

from __future__ import annotations

from typing import Union

from . import _native
from .apk import APK

__all__ = ["AnalyzeAPK", "load_index"]


def raise_load_error(rs) -> None:
    """Raise what androguard 4.1.3's AnalyzeAPK raises for the APK `rs` was
    loaded from (with ``header_errors=True``), if anything: the first, in
    load order, of a DEX ``DEX()`` rejects and the method ``Analysis.add()``
    can't disassemble (add() of every earlier DEX runs before a later DEX is
    parsed)."""
    errs = rs.header_errors()
    inv = rs.first_invalid()
    if inv is not None and (not errs or rs.dex_positions()[inv[0]] < errs[0][0]):
        raise inv[3]
    if errs:
        _pos, _name, kind, message = errs[0]
        raise (NotImplementedError if kind == "NotImplementedError" else ValueError)(message)


def load_index(_file: Union[str, bytes], raw: bool = False, tolerant: bool = False):
    """The native index for an APK path (or, with ``raw=True``, its bytes),
    failing as AnalyzeAPK does unless ``tolerant``."""
    if tolerant:
        return _native.Apk.from_bytes(_file) if raw else _native.Apk(_file)
    rs = _native.Apk.from_bytes(_file, header_errors=True) if raw else _native.Apk(_file, header_errors=True)
    raise_load_error(rs)
    return rs


def AnalyzeAPK(_file: Union[str, bytes], session=None, raw: bool = False, tolerant: bool = False):
    """``(APK, [DEX], Analysis)`` for a path or, with ``raw=True``, the APK's
    bytes."""
    if session:
        raise NotImplementedError("androguard_rs: AnalyzeAPK(session=...) is not implemented")
    from ._analysis import Analysis
    from .dex import DEX

    a = APK(_file, raw=raw)
    rs = load_index(_file, raw=raw, tolerant=tolerant)
    dx = Analysis(rs, a)
    api = a.get_target_sdk_version()
    d = [DEX._of(rs, i, api if api else 16) for i in range(rs.dex_count())]
    dx._views = d
    return a, d, dx
