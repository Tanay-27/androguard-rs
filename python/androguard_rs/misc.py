"""``androguard.misc.AnalyzeAPK`` drop-in.

``AnalyzeAPK(path)`` / ``AnalyzeAPK(data, raw=True)`` returns ``(a, d, dx)``
like androguard 4.1.3: ``a`` is ``androguard_rs.apk.APK``, ``d`` the list of
``androguard_rs.dex.DEX`` objects (one per DEX file, in load order, served
lazily from the index) and ``dx`` the lazy ``Analysis`` facade over
``androguard_rs.Apk`` (``androguard_rs._analysis``). Sessions aren't
supported.

Importing it raises the recursion limit to 5000, as importing
``androguard.misc`` does (through ``androguard.decompiler``).

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

import sys as _sys

from . import _agerr, _native
from . import decompiler as _decompiler  # noqa: F401  androguard.misc's import side effect: recursion limit 5000
from .apk import APK

__all__ = ["AnalyzeAPK", "load_index"]


def raise_load_error(rs) -> None:
    """Raise what androguard 4.1.3's AnalyzeAPK raises for the APK `rs` was
    loaded from (with ``header_errors=True``), if anything: the first DEX,
    in load order, that ``DEX()`` or ``Analysis.add()`` fails on (add() of
    every earlier DEX runs before a later DEX is parsed), else what
    ``create_xref()`` raises."""
    err = rs.load_error()
    if err is not None:
        raise _agerr.make(err)


def load_index(_file: Union[str, bytes], raw: bool = False, tolerant: bool = False, _depth=None):
    """The native index for an APK path (or, with ``raw=True``, its bytes),
    failing as AnalyzeAPK does unless ``tolerant``. ``_depth``: (frames, C
    units) androguard would have left in its ``DEX.__init__``; by default,
    as if our caller were androguard's AnalyzeAPK."""
    if tolerant:
        return _native.Apk.from_bytes(_file) if raw else _native.Apk(_file)
    if _depth is None:
        # androguard's DEX.__init__ would be instantiated by our caller.
        _depth = (_agerr.max_depth(_sys._getframe(1)) - 1, _agerr.c_units() - 2)
    kw = dict(header_errors=True, max_depth=_depth[0], c_budget=_depth[1])
    rs = _native.Apk.from_bytes(_file, **kw) if raw else _native.Apk(_file, **kw)
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
    # androguard's DEX.__init__ runs one frame below AnalyzeAPK, instantiated
    # from it (two C recursion units).
    depth = (_agerr.max_depth(_sys._getframe(0)) - 1, _agerr.c_units() - 2)
    rs = load_index(_file, raw=raw, tolerant=tolerant, _depth=depth)
    dx = Analysis(rs, a)
    api = a.get_target_sdk_version()
    d = [DEX._of(rs, i, api if api else 16) for i in range(rs.dex_count())]
    dx._views = d
    return a, d, dx
