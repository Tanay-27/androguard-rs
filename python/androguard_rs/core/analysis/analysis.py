"""``androguard.core.analysis.analysis``: the module ``androguard_rs.analysis``
itself."""

import sys

from ... import analysis as _module

sys.modules[__name__] = _module
