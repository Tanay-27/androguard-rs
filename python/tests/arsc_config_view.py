"""What an ARSCResTableConfig shows, for comparing ours with androguard's."""

METHODS = ("get_qualifier", "get_config_name_friendly", "get_language_and_region", "get_language",
           "get_country", "get_density", "is_default", "_get_tuple")


def config_view(c):
    return (type(c).__name__, sorted(vars(c).items()), repr(c), hash(c), [getattr(c, m)() for m in METHODS])


def tree_view(items):
    """A get_resolved_res_configs() result with each config as config_view()."""
    out = []
    for it in items:
        if isinstance(it, tuple):
            c, v = it
            out.append((config_view(c), tree_view(v) if isinstance(v, list) else v))
        else:
            out.append(it)
    return out
