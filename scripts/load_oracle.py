"""Run AnalyzeAPK's per-DEX load sequence (DEX(), Analysis.add(),
create_xref()) on DEX bytes and describe the outcome: ("ok",) or (stage, type name, repr(args), str(e)).

    side = "ag" (androguard 4.1.3) or "rs" (androguard_rs drop-ins)
"""
import sys


def setup(side):
    if side == "ag":
        from loguru import logger
        logger.remove()
        from androguard.core.dex import DEX
        from androguard.core.analysis.analysis import Analysis
    else:
        from androguard_rs.dex import DEX
        from androguard_rs.analysis import Analysis
    return DEX, Analysis


def describe(e, stage):
    try:
        a = repr(e.args)
    except Exception as x:  # noqa
        a = "<repr failed %r>" % (x,)
    try:
        s = str(e)
    except Exception as x:  # noqa
        s = "<str failed %r>" % (x,)
    return (stage, type(e).__name__, a, s)


def view(dexes, dx):
    """What the loaded objects show: every class, its methods (names,
    descriptors, flags) and their instruction text, plus the Analysis's
    classes and xrefs of each method."""
    out = []
    for d in dexes:
        for c in d.get_classes():
            ms = []
            for m in c.get_methods():
                try:
                    ins = [(i.get_name(), i.get_output()) for i in m.get_instructions()]
                except Exception as e:  # noqa
                    ins = ("EXC", type(e).__name__, str(e))
                ms.append((m.get_name(), m.get_descriptor(), m.get_access_flags_string(), str(m), ins))
            fs = [(f.get_name(), f.get_descriptor(), str(f.get_access_flags_string())) for f in c.get_fields()]
            out.append((c.get_name(), c.get_superclassname(), list(c.get_interfaces()), ms, fs))
    xs = []
    for ca in sorted(dx.get_classes(), key=lambda c: c.name):
        for ma in ca.get_methods():
            xs.append((str(ma.method), sorted(str(x[1].method) + "@" + str(x[2]) for x in ma.get_xref_from()),
                       sorted(str(x[1].method) + "@" + str(x[2]) for x in ma.get_xref_to())))
    xs.sort()
    return out, xs


def run(DEX, Analysis, blobs, deep=False):
    """blobs: list of DEX bytes, added to one Analysis in order (as AnalyzeAPK)."""
    stage = "DEX"
    try:
        dx = Analysis()
        dexes = []
        for b in blobs:
            stage = "DEX"
            d = DEX(b)
            dexes.append(d)
            stage = "add"
            dx.add(d)
        stage = "xref"
        dx.create_xref()
        if deep:
            stage = "view"
            return ("ok", view(dexes, dx))
        return ("ok",)
    except RecursionError as e:
        return describe(e, stage)
    except Exception as e:
        return describe(e, stage)
