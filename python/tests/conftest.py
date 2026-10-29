"""Without androguard (or mutf8) installed, skip the test modules that
compare against them live (they import them at module level); everything
that runs on stored goldens still runs."""

import importlib.util
import re
from pathlib import Path

_MISSING = [m for m in ("androguard", "loguru", "mutf8") if importlib.util.find_spec(m) is None]
if _MISSING:
    _IMPORTS = re.compile(rf"^(?:from|import) (?:{'|'.join(_MISSING)})\b", re.M)
    collect_ignore = sorted(p.name for p in Path(__file__).parent.glob("test_*.py")
                            if _IMPORTS.search(p.read_text(encoding="utf-8")))
