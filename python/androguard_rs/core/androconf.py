"""``androguard.core.androconf``: ``load_api_specific_resource_module``,
``InvalidResourceError`` and the ``CONF["DEFAULT_API"]`` it falls back to.
androguard's log messages are not emitted; the rest of androconf (colors,
file type sniffing, session settings) is not provided."""

from __future__ import annotations

from typing import Union

from ..api_specific_resources import load_permission_mappings, load_permissions

__all__ = ["CONF", "InvalidResourceError", "load_api_specific_resource_module"]


class InvalidResourceError(Exception):
    """Raised by ``load_api_specific_resource_module`` for an unknown
    resource name."""


CONF = {"DEFAULT_API": 16}


def load_api_specific_resource_module(resource_name: str, api: Union[str, int, None] = None) -> dict:
    """``aosp_permissions`` (``load_permissions``) or ``api_permission_mappings``
    (``load_permission_mappings``) for an API level (default
    ``CONF["DEFAULT_API"]``), falling back to the default level when there
    is nothing for it."""
    loader = dict(aosp_permissions=load_permissions, api_permission_mappings=load_permission_mappings)

    if resource_name not in loader:
        raise InvalidResourceError("Invalid Resource '{}', not in [{}]".format(resource_name, ", ".join(loader.keys())))

    if not api:
        api = CONF["DEFAULT_API"]

    ret = loader[resource_name](api)

    if ret == {}:
        ret = loader[resource_name](CONF['DEFAULT_API'])

    return ret
