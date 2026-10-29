"""``androguard.core.api_specific_resources.load_permission_mappings``, over
the API/permission mapping data vendored from androguard 4.1.3 (Apache-2.0;
see VENDORED.md next to this file, python/licenses/androguard-VENDORED.md)."""

from __future__ import annotations

import json
import os
from typing import Union


def load_permission_mappings(apilevel: Union[str, int]) -> dict[str, list[str]]:
    """The {method signature: [permissions]} mapping for an API level, or {}
    if there is none for exactly that level (as androguard)."""
    root = os.path.dirname(os.path.realpath(__file__))
    permissions_file = os.path.join(root, "api_permission_mappings", "permissions_{}.json".format(apilevel))
    if not os.path.isfile(permissions_file):
        return {}
    with open(permissions_file, "r") as fp:
        return json.load(fp)
