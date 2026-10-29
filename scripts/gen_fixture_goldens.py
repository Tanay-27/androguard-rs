"""Regenerate python/tests/fixture_goldens.py: what androguard 4.1.3 (with
mutf8 1.1.0) answers on python/tests/fixture_apk.py's APK, for the
standalone tests, which then run without androguard.

    python scripts/gen_fixture_goldens.py      # in a venv with androguard 4.1.3

The APK with com/ex/Bad can't be loaded by androguard at all, so goldens
come from the APK without it; for Bad's bytecode the golden is str() of
the InvalidInstruction androguard's disassembler raises on that code.
"""

import pprint
import re
import sys
import tempfile
from pathlib import Path

from loguru import logger

logger.disable("androguard")

HERE = Path(__file__).resolve().parent
TESTS = HERE.parent / "python" / "tests"
sys.path.insert(0, str(TESTS))

from androguard.core.axml import ARSCParser  # noqa: E402
from androguard.core.dex import DCode  # noqa: E402
from androguard.misc import AnalyzeAPK  # noqa: E402

import fixture_apk as fx  # noqa: E402
from resource_refs import resource_refs  # noqa: E402

ADDR = re.compile(r" at 0x[0-9a-f]+>")
NEEDLES = [["stringbuilder"], ["0x7f0b0001"], ["https://"], ["v0, v1"], ["lcom/ex/base;"], ["nothing-matches"]]
PATTERNS = [".*", "Lcom/ex/", "Ljava/", ".*R\\$", "Lcom/ex/Main;", "com"]
STRINGS = ["https", "Bearer", "Main", "zz-none"]


def sig(ma):
    return f"{ma.class_name}->{ma.name}{ma.descriptor.replace(' ', '')}"


def typed(v):
    if isinstance(v, list):
        return ("list", [typed(x) for x in v])
    if v is None or isinstance(v, (bool, int, str)):
        return (type(v).__name__, v)
    return ("object", ADDR.sub(" at 0x0>", repr(v)))


def init_text(f):
    iv = getattr(f, "init_value", None)
    return "<no encoded init value>" if iv is None else ADDR.sub(" at 0x0>", repr(iv.value))


def main():
    with tempfile.TemporaryDirectory() as d:
        path = fx.build_apk(Path(d) / "fixture.apk")
        a, _, dx = AnalyzeAPK(path)
        g = {}
        g["classes"] = [(c.name, c.is_external()) for c in dx.get_classes()]
        g["class_methods"] = {
            c.name: [(sig(m), m.get_method().get_name(), m.get_method().get_descriptor(),
                      m.get_method().get_access_flags_string(), m.is_external()) for m in c.get_methods()]
            for c in dx.get_classes()}
        g["class_fields"] = {
            c.name: [(f.get_class_name(), f.get_access_flags_string(), f.name, f.get_descriptor(),
                      None if f.init_value is None else (ADDR.sub(" at 0x0>", repr(f.init_value.value)),
                                                         typed(f.init_value.value)))
                     for f in (fa.get_field() for fa in c.get_fields())]
            for c in dx.get_classes()}
        xf, xt, has_code, bytecode = {}, {}, {}, {}
        for ma in dx.get_methods():
            s = sig(ma)
            row = lambda c, m, off: (sig(m), c.name, m.get_method().get_name(), m.get_method().get_descriptor(), off)  # noqa: E731
            xf.setdefault(s, []).extend(row(*x) for x in ma.get_xref_from())
            xt.setdefault(s, []).extend(row(*x) for x in ma.get_xref_to())
            if ma.is_external():
                continue
            em = ma.get_method()
            has_code[s] = em.get_code() is not None
            bytecode[s] = None if em.get_code() is None else [
                (off, i.get_name(), i.get_output()) for off, i in em.get_instructions_idx()]
        g["xref_from"] = {k: sorted(v) for k, v in xf.items()}
        g["xref_to"] = {k: sorted(v) for k, v in xt.items()}
        g["has_code"] = has_code
        g["bytecode"] = bytecode
        g["hierarchy"] = [(c.name, c.get_class().get_superclassname(), list(c.get_class().get_interfaces()))
                          for c in dx.get_classes() if not c.is_external()]
        g["class_info"] = {}
        for c in dx.get_classes():
            if c.is_external():
                continue
            cd = c.get_class()
            g["class_info"][c.name] = {
                "name": cd.get_name(), "access_flags": cd.get_access_flags_string(),
                "superclass": cd.get_superclassname(), "interfaces": list(cd.get_interfaces()),
                "methods": [(m.get_name(), m.get_descriptor(), m.get_access_flags_string()) for m in cd.get_methods()],
                "fields": [(f.get_access_flags_string(), f.get_name(), f.get_descriptor(), init_text(f))
                           for f in cd.get_fields()],
            }
        for jumbo in (False, True):
            wanted = ("const-string", "const-string/jumbo") if jumbo else ("const-string",)
            rows = []
            for c in dx.get_classes():
                if c.is_external():
                    continue
                for ma in c.get_methods():
                    if ma.is_external() or ma.get_method().get_code() is None:
                        continue
                    em = ma.get_method()
                    outs = [i.get_output() for _, i in em.get_instructions_idx() if i.get_name() in wanted]
                    if outs:
                        rows.append((c.name, em.get_name(), em.get_descriptor(), tuple(outs)))
            g[f"const_strings_{jumbo}"] = rows
        # Lower-cased instruction-text matching (see test_parity.test_search_instruction_text)
        blob = []
        for c in dx.get_classes():
            if c.is_external():
                continue
            for ma in c.get_methods():
                try:
                    outs = [o.lower() for _, i in ma.get_method().get_instructions_idx() if (o := i.get_output())]
                except Exception:
                    continue
                if outs:
                    blob.append((ma, outs))
        g["search"] = [(n, [sig(ma) for ma, outs in blob if any(x in o for o in outs for x in n)]) for n in NEEDLES]
        g["find_classes"] = [(p, ne, [c.name for c in dx.find_classes(p, ne)]) for p in PATTERNS for ne in (False, True)]
        g["methods_using_string"] = [
            (n, sorted({sig(m) for s, sa in dx.strings.items() if n in s for _, m in sa.get_xref_from()}))
            for n in STRINGS]
        g["resource_refs"] = resource_refs(dx)
        arsc = ARSCParser(fx.arsc())
        rids = sorted(arsc.resource_values)
        g["arsc"] = {
            "packages": arsc.get_packages_names(),
            "public": arsc.get_public_resources("com.example"),
            "strings": arsc.get_resolved_strings(),
            "names": [(r, arsc.get_resource_xml_name(r)) for r in rids],
            "configs": [(r, [(c._get_tuple(), v) for c, v in arsc.get_resolved_res_configs(r)]) for r in rids],
        }
        # Bad's code alone, through androguard's disassembler.
        try:
            raw = fx.bad_class()["direct"][0][4](None)
            list(DCode(dx.vms[0].CM, 0, len(raw) // 2, raw).get_instructions())
            raise SystemExit("expected InvalidInstruction")
        except Exception as e:  # noqa: BLE001
            g["bad_bytecode_error"] = (type(e).__name__, str(e))

    out = TESTS / "fixture_goldens.py"
    out.write_text(
        '"""Goldens for test_standalone.py / test_compat.py: androguard 4.1.3 (mutf8\n'
        "1.1.0) on fixture_apk.py's APK. Generated by scripts/gen_fixture_goldens.py;\n"
        'regenerate rather than edit."""\n\n'
        "# fmt: off\nG = " + pprint.pformat(g, width=120, sort_dicts=False) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
