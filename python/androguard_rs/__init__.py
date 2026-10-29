"""androguard_rs: the native module (DEX index, resources, binary XML, zip),
re-exported here, plus pure-Python drop-ins for androguard 4.1.3's modules,
under androguard's own paths (``androguard`` renamed to ``androguard_rs``):

- ``androguard_rs.core.apk``: ``APK``, ``FileNotPresent``, ...
- ``androguard_rs.core.dex``: ``DEX``, ``ClassDefItem``, ``EncodedMethod``,
  ``DalvikCode``, ``DCode``, the ``Instruction*`` classes, ...
- ``androguard_rs.core.analysis.analysis``: ``Analysis``, ``ClassAnalysis``,
  ``MethodAnalysis``
- ``androguard_rs.core.axml``: ``AXMLPrinter``, ``ARSCParser``, ...
- ``androguard_rs.core.api_specific_resources``: ``load_permissions``,
  ``load_permission_mappings``
- ``androguard_rs.core.androconf``: ``load_api_specific_resource_module``
- ``androguard_rs.misc``: ``AnalyzeAPK``
- ``androguard_rs.util``: ``set_log``
- ``androguard_rs.decompiler``: only the import's recursion-limit side effect

The short paths ``androguard_rs.apk``, ``.dex``, ``.analysis``, ``.axml`` and
``.api_specific_resources`` are the same modules as their ``core`` paths.
"""

from . import androguard_rs as _native
from .androguard_rs import *  # noqa: F401,F403

# Private helpers (test hooks) too, so `androguard_rs._x` keeps working.
for _k in dir(_native):
    if not _k.startswith("__"):
        globals()[_k] = getattr(_native, _k)
del _k
