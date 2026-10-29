"""sig_cases.py without androguard: string xrefs through const-string/jumbo's
signed index (and androguard's text for invalid indices and strings) in
Apk.methods_using_string(), and by-signature queries on a class whose name
contains "->". Goldens (sig_goldens.py) were generated once from androguard
4.1.3 + mutf8 1.1.0 by scripts/gen_dexobj_goldens.py; test_sig_parity.py
checks live."""

import androguard_rs
import sig_cases as K
from sig_goldens import GOLDEN


def test_methods_using_string():
    assert K.rs_strings(androguard_rs.Apk.from_bytes(K.strings_apk())) == GOLDEN["strings"]


def test_arrow_class_names():
    assert K.rs_arrow(androguard_rs.Apk.from_bytes(K.arrow_apk())) == GOLDEN["arrow"]


def test_lone_surrogate_needle():
    # A needle with a lone surrogate is accepted (matches nothing here).
    assert androguard_rs.Apk.from_bytes(K.strings_apk()).methods_using_string("\ud800") == []
