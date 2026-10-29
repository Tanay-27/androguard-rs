"""``androguard.core.analysis.analysis.Analysis`` drop-in for code that builds
the analysis itself from per-DEX objects::

    # from androguard.core.dex import DEX
    # from androguard.core.analysis.analysis import Analysis
    from androguard_rs.dex import DEX
    from androguard_rs.analysis import Analysis

    vmx = Analysis()
    for raw in apk.get_all_dex():
        try:
            vm = DEX(raw)          # androguard's header checks and errors
            vmx.add(vm)            # InvalidInstruction as androguard's add()
            vms.append(vm)
            vm.set_analysis(vmx)
        except ValueError as e:    # "Header too small", "Wrong endian tag", ...
            ...
    vmx.create_xref()              # indexes every added DEX together

``add(vm)`` keeps the DEX (its bytes) and, as androguard's ``add()`` does,
raises ``InvalidInstruction`` for the DEX's first method androguard can't
disassemble (after appending it to ``vms``). ``create_xref()`` builds one
native index (``androguard_rs.Apk``) over every added DEX, in order, and binds
each DEX object to it (their bytes are then dropped). The rest is the lazy
facade over that index (``androguard_rs._analysis.Analysis``:
``get_classes()``, ``get_class_analysis()``, ``find_methods()``,
``MethodAnalysis``, ...). Queries made before ``create_xref()`` build the
index then, as if it had run (androguard would answer without xrefs).
"""

from __future__ import annotations

from . import _native
from ._analysis import Analysis as _Facade
from ._analysis import ClassAnalysis, MethodAnalysis  # noqa: F401
from .dex import DEX

__all__ = ["Analysis", "ClassAnalysis", "MethodAnalysis"]


class Analysis(_Facade):
    __slots__ = ("_rs_index", "_added", "_xrefs_done")

    def __init__(self, vm: DEX | None = None) -> None:
        self._added = []
        self._xrefs_done = False
        self._rs_index = None
        super().__init__(None, None)
        if vm:
            self.add(vm)

    # The facade reads self._rs; here it is built on first use.
    @property
    def _rs(self):
        if self._rs_index is None:
            self._build()
        return self._rs_index

    @_rs.setter
    def _rs(self, value):
        self._rs_index = value

    def _build(self) -> None:
        dexes = self._added
        for vm in dexes:
            if vm._raw is None:
                raise NotImplementedError("androguard_rs.analysis: a DEX can only be added before create_xref()")
        rs = _native.Apk.from_dex_list([vm._raw for vm in dexes])
        for d, vm in enumerate(dexes):
            vm._bind(rs, d)
        self._rs_index = rs
        self._views = list(dexes)

    @property
    def vms(self) -> list:
        return self._added

    def add(self, vm: DEX) -> None:
        if not isinstance(vm, DEX) or vm._raw is None:
            raise NotImplementedError("androguard_rs.analysis.Analysis.add() takes an androguard_rs.dex.DEX made from bytes")
        if self._rs_index is not None:
            raise NotImplementedError("androguard_rs.analysis: add() after the index was built")
        self._added.append(vm)
        exc = _native._dex_first_invalid(vm._raw)
        if exc is not None:
            raise exc

    def create_xref(self) -> None:
        if self._xrefs_done:
            # androguard logs an error and returns.
            return
        self._xrefs_done = True
        if self._rs_index is None:
            self._build()
