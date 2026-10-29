"""``androguard.decompiler`` stand-in: only its import side effect.

androguard 4.1.3's ``androguard/decompiler/__init__.py`` runs
``sys.setrecursionlimit(5000)`` when imported (``androguard.misc`` imports
it too), which raises the depth at which androguard's own recursive parsing
(nested encoded values in ``DEX()``) and everything else in the process
hits RecursionError. Importing this module does the same, so code that
dropped its decompiler import keeps androguard's limit. The decompiler
itself (``decompile``, ``DecompilerDAD``) is not provided.
"""

import sys

sys.setrecursionlimit(5000)


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"androguard_rs: androguard.decompiler.{name} is not provided")
