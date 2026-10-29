"""Resource-id cross-references through the public object model, on any
androguard-shaped Analysis (androguard's own, or the androguard_compat
facade's).

Used by test_compat.py, test_compat_parity.py and
scripts/gen_fixture_goldens.py. It exercises, together: the typed ``int``
of an ``R$<type>`` static field's ``init_value.value``, instruction
literals via ``get_code().get_bc().get_instructions()`` and
``get_literals()``, and ``EncodedMethod.name``.
"""


def r_field_ids(dx) -> dict:
    """{(resource type, field name): id} for every static field of an
    ``R$<type>`` class whose initial value is an ``int`` (not a bool)."""
    ids = {}
    for ca in dx.get_classes():
        cut = ca.name.rfind("R$")
        if ca.is_external() or cut < 0:
            continue
        rtype = ca.name[cut + 2:].rstrip(";")
        for fa in ca.get_fields():
            field = fa.get_field()
            init = getattr(field, "init_value", None)
            if init is not None and type(init.value) is int:
                ids[(rtype, field.name)] = init.value
    return ids


def literal_users(dx, wanted) -> dict:
    """{literal: sorted [(class, EncodedMethod.name, instruction name)]} for
    every instruction of a defined method whose literals include one of
    `wanted`."""
    hits = {v: set() for v in wanted}
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        for ma in ca.get_methods():
            if ma.is_external():
                continue
            em = ma.get_method()
            code = em.get_code()
            if not code:
                continue
            for ins in code.get_bc().get_instructions():
                # Payloads (packed/sparse-switch, fill-array-data) aren't
                # Instructions and have no get_literals(), in androguard too.
                get_literals = getattr(ins, "get_literals", None)
                for lit in get_literals() if get_literals else ():
                    if lit in hits:
                        hits[lit].add((ca.name, em.name, ins.get_name()))
    return {v: sorted(found) for v, found in hits.items()}


def resource_refs(dx) -> list:
    """[(type, name, "0x%08x" id, users)] for every R field id, sorted."""
    ids = r_field_ids(dx)
    users = literal_users(dx, set(ids.values()))
    return sorted((rtype, name, f"0x{rid:08x}", users[rid]) for (rtype, name), rid in ids.items())
