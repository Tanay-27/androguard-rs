"""androguard_rs: the native module (DEX index, resources, binary XML, zip),
re-exported here, plus pure-Python drop-ins for androguard 4.1.3 entry points:

- ``androguard_rs.apk``: ``APK``, ``FileNotPresent`` (``androguard.core.apk``)
- ``androguard_rs.axml``: ``AXMLPrinter`` (``androguard.core.axml``)
- ``androguard_rs.misc``: ``AnalyzeAPK`` (``androguard.misc``)
- ``androguard_rs.util``: ``set_log`` (``androguard.util``)
- ``androguard_rs.api_specific_resources``: ``load_permission_mappings``
"""

from . import androguard_rs as _native
from .androguard_rs import *  # noqa: F401,F403

# Private helpers (test hooks) too, so `androguard_rs._x` keeps working.
for _k in dir(_native):
    if not _k.startswith("__"):
        globals()[_k] = getattr(_native, _k)
del _k
