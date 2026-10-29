"""Two by-index / by-signature corners, shared by test_sig.py (standalone,
goldens), test_sig_parity.py (live) and scripts/gen_dexobj_goldens.py
(which wrote sig_goldens.py once from androguard 4.1.3 + mutf8 1.1.0):

- const-string/jumbo's string index is a signed int in androguard (31c is
  unpacked "BBi") used as a Python list index: 0xFFFFFFFF is the DEX's last
  string, 0x80000000 is out of range ("AG:IS: invalid string", as is
  const-string's index past the table). create_xref() records the use of
  the string so resolved, which is what dx.get_strings() xrefs (and so
  Apk.methods_using_string) see. Strings
  that aren't valid MUTF-8 show as androguard's "ANDROGUARD[INVALID_STRING]
  ..." text.
- A class name may contain "->" (crafted files): by-signature lookups
  (Apk.bytecode/has_code/xref_from/xref_to with "Lcls;->name(...)R")
  must find the method of that class, also when it is defined more than
  once (resolved as androguard's (class, name, descriptor) table does).
"""

import dup_cases as K
from dup_cases import _code, apk, call, cls, init, m, string
from fixture_apk import const_string, const_string_jumbo

S = "Lp/S;"


def strings_apk() -> bytes:
    c = cls(S, direct=[init()], virtual=[
        m("last", lambda c: const_string_jumbo(0, 0xFFFFFFFF)),
        m("second_last", lambda c: const_string_jumbo(0, 0xFFFFFFFE)),
        m("neg_out", lambda c: const_string_jumbo(0, 0x80000000)),
        m("pos_out", lambda c: const_string_jumbo(0, 0x7FFFFFFF)),
        m("short_out", lambda c: const_string(0, 0xFFFF)),
        m("plain", string("plain text")),
        m("jumbo", lambda c: const_string_jumbo(0, c.s("jumbo text"))),
        m("accent", string("café")),
        m("emoji", string("smile \U0001F600")),
        m("zzz", string("zzz last")),  # sorts last: the string 0xFFFFFFFF names
    ])
    return apk([c])


NEEDLES = ["", "AG:IS", "invalid string", "zzz", "zzz last", "text", "jumbo", "café", "é", "\U0001F600",
           "INVALID", "smile", "p/S", "nothing", "z"]


def sig(ma) -> str:
    return f"{ma.class_name}->{ma.name}{ma.descriptor.replace(' ', '')}"


def ag_strings(dx) -> dict:
    """A string search over androguard's dx: per needle, the
    signatures of methods using a string that contains it."""
    return {n: sorted({sig(m) for s in dx.get_strings() if n in s.get_value() for _, m in s.get_xref_from()})
            for n in NEEDLES}


def rs_strings(apk_) -> dict:
    return {n: sorted(apk_.methods_using_string(n)) for n in NEEDLES}


# A class whose name contains "->", defined in three DEX files (so its
# methods resolve through androguard's (class, name, descriptor) table), and
# a class "Lp/A;" whose names make a misread signature plausible.
A, ARROW = "Lp/A;", "Lp/A->b;"


def arrow_apk() -> bytes:
    c1 = cls(ARROW, direct=[init()], virtual=[
        m("a", string("a-1"), call(0x6E, ARROW, "mid")),
        m("one", string("one-1"))])
    c2 = cls(ARROW, direct=[init()], virtual=[
        m("a", string("a-2")),
        m("mid", string("mid-2"), call(0x6E, ARROW, "a"))])
    c3 = cls(ARROW, direct=[init()], virtual=[m("a", string("a-3"), call(0x6E, ARROW, "mid"))])
    plain = cls(A, direct=[init()], virtual=[m("b", string("A.b")), m("go", call(0x6E, ARROW, "a"), call(0x6E, ARROW, "one"))])
    return apk([c1, plain], [c2], [c3])


ARROW_METHODS = [(ARROW, "a", "()V"), (ARROW, "mid", "()V"), (ARROW, "one", "()V"), (ARROW, "<init>", "()V"),
                 (A, "b", "()V"), (A, "go", "()V")]


def _code_text(ma):
    if ma is None:
        return None
    em = ma.get_method()
    code = em.get_code() if hasattr(em, "get_code") else None
    return None if code is None else [(off, i.get_name(), i.get_output()) for off, i in em.get_instructions_idx()]


def ag_arrow(dx) -> list:
    """For each method: what androguard's (class, name, descriptor) table
    resolves it to (get_method_analysis_by_name): its code and xrefs."""
    out = []
    for c, n, d in ARROW_METHODS:
        ma = dx.get_method_analysis_by_name(c, n, d)
        xf = None if ma is None else sorted((r.class_name, r.name, r.descriptor, off) for _, r, off in ma.get_xref_from())
        xt = None if ma is None else sorted((r.class_name, r.name, r.descriptor, off) for _, r, off in ma.get_xref_to())
        out.append((c, n, d, _code_text(ma), xf, xt))
    return out


def rs_arrow(apk_) -> list:
    """The same through androguard_rs.Apk's by-signature queries."""
    out = []
    for c, n, d in ARROW_METHODS:
        s = f"{c}->{n}{d}"
        rows = apk_.bytecode(s)
        code = None if rows is None else [tuple(r) for r in rows]
        xf = sorted((r[1] if len(r) < 7 else r[6], r[2], r[3], r[4]) for r in apk_.xref_from(s))
        xt = sorted((r[1] if len(r) < 7 else r[6], r[2], r[3], r[4]) for r in apk_.xref_to(s))
        out.append((c, n, d, code, xf, xt))
    return out


CASES = {"strings": strings_apk, "arrow": arrow_apk}
_ = (K, _code)
