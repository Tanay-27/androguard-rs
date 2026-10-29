"""``androguard.core.api_specific_resources``: ``load_permissions`` and
``load_permission_mappings``, over the AOSP permission lists and the
API/permission mapping data vendored from androguard 4.1.3 (Apache-2.0; see
VENDORED.md next to this file, python/licenses/androguard-VENDORED.md).
androguard's log messages are not emitted."""

from __future__ import annotations

import json
import os
import re
from typing import Union


class APILevelNotFoundError(Exception):
    pass


def load_permissions(apilevel: Union[str, int], permtype: str = 'permissions') -> dict[str, dict[str, str]]:
    """The {permission name: info} (or, with ``permtype='groups'``, the
    permission groups) of an API level, as androguard: a level above or below
    the ones available gives the highest or lowest one, a missing level
    between two gives the lower one."""
    if permtype not in ['permissions', 'groups']:
        raise ValueError("The type of permission list is not known.")

    apilevel = int(apilevel)

    root = os.path.dirname(os.path.realpath(__file__))
    permissions_file = os.path.join(root, "aosp_permissions", "permissions_{}.json".format(apilevel))

    levels = filter(lambda x: re.match(r'^permissions_\d+\.json$', x), os.listdir(os.path.join(root, "aosp_permissions")))
    levels = list(map(lambda x: int(x[:-5].split('_')[1]), levels))

    if not levels:
        return {}

    if not os.path.isfile(permissions_file):
        if apilevel > max(levels):
            return load_permissions(max(levels), permtype)
        if apilevel < min(levels):
            return load_permissions(min(levels), permtype)
        lower_level = max(filter(lambda x: x < apilevel, levels))
        return load_permissions(lower_level, permtype)

    with open(permissions_file, "r") as fp:
        return json.load(fp)[permtype]


def load_permission_mappings(apilevel: Union[str, int]) -> dict[str, list[str]]:
    """The {method signature: [permissions]} mapping for an API level, or {}
    if there is none for exactly that level (as androguard)."""
    root = os.path.dirname(os.path.realpath(__file__))
    permissions_file = os.path.join(root, "api_permission_mappings", "permissions_{}.json".format(apilevel))
    if not os.path.isfile(permissions_file):
        return {}
    with open(permissions_file, "r") as fp:
        return json.load(fp)
