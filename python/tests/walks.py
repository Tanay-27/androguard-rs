"""Reference walks over the androguard API (androguard's own Analysis or
the facade's) that Analysis.const_strings() and
Analysis.search_instruction_text() answer natively."""


def _outs(ma):
    if ma.is_external():
        return []
    try:
        return [(ins.get_name(), ins.get_output()) for _off, ins in ma.get_method().get_instructions_idx()]
    except Exception:  # a method androguard can't disassemble contributes nothing
        return []


def const_strings_walk(dx):
    """[(class, [(name, descriptor without spaces, [const-string outputs])])],
    internal classes only, methods without a const-string left out."""
    rows = []
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        methods = []
        for ma in ca.get_methods():
            outs = [out for name, out in _outs(ma) if name == "const-string"]
            if outs:
                methods.append((ma.name, ma.descriptor.replace(" ", ""), outs))
        if methods:
            rows.append((ca.name, methods))
    return rows


def search_walk(dx, needles):
    """(class, method class, name, descriptor) of each internal class's
    method one of whose instructions' get_output().lower() contains a needle."""
    hits = []
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        for ma in ca.get_methods():
            outs = [out.lower() for _name, out in _outs(ma) if out]
            if any(n in out for out in outs for n in needles):
                hits.append((ca.name, ma.class_name, ma.name, ma.descriptor))
    return hits


def native_const_strings(dx):
    return [(cls, [(n, d.replace(" ", ""), list(o)) for n, d, o in methods]) for cls, methods in dx.const_strings()]


def native_search(dx, needles):
    return [(ca.name, ma.class_name, ma.name, ma.descriptor) for ca, ma in dx.search_instruction_text(needles)]


NEEDLES = [["ljava/lang/string;"], ["const-string"], ["http"], ["landroid/"], ["v0, v1"], ['"'], ["\\"], ["zzzz-no-match"]]
