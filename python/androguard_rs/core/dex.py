"""``androguard.core.dex``: the module ``androguard_rs.dex`` itself."""

import sys

from .. import dex as _module

sys.modules[__name__] = _module
