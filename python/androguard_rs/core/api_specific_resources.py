"""``androguard.core.api_specific_resources``: the module
``androguard_rs.api_specific_resources`` itself."""

import sys

from .. import api_specific_resources as _module

sys.modules[__name__] = _module
