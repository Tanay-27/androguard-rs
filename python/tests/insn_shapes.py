"""What an androguard caller can observe of a method's
instructions, as plain comparable data. Works on androguard 4.1.3's
EncodedMethod and on the facade's, so parity tests and the golden
generator (scripts/gen_insn_goldens.py) share one definition.

Default object reprs (androguard's payloads have no __str__, so str() is
`<androguard.core.dex.PackedSwitch object at 0x...>`) are compared without
module and address: the address differs between any two runs, and the
module is androguard_rs.dex here.
"""

import re

_OBJ = re.compile(r"<(?:[\w.]+\.)?(\w+) object at 0x[0-9a-f]+>")

FIELDS = ("OP", "A", "B", "C", "D", "E", "F", "G", "AA", "BB", "CC", "AAAA", "BBBB", "CCCC", "HHHH", "NNNN",
          "AAAAAAAA", "BBBBBBBB", "CCCCCCCC", "BBBBBBBBBBBBBBBB", "_Instruction21h__BBBB", "ident", "size",
          "first_key", "targets", "keys", "element_width", "data", "format_general_size", "length")

CALLS = ("get_name", "get_op_value", "get_length", "get_raw", "get_operands", "get_translated_kind", "get_output",
         "get_literals", "get_kind", "get_ref_kind", "get_ref_off", "get_string", "get_hex", "disasm",
         "get_keys", "get_values", "get_targets", "get_data", "get_formatted_operands", "get_notes")


def outcome(f, *args):
    """("ok", repr(value), type name) or ("raise", exception type, str(exc))."""
    try:
        v = f(*args)
    except Exception as e:  # noqa: BLE001 - the exception is the result
        return ("raise", type(e).__name__, str(e))
    return ("ok", _OBJ.sub(r"<\1 object>", repr(v)), type(v).__name__)


def insn_shape(ins) -> tuple:
    calls = tuple((c, outcome(lambda: getattr(ins, c)())) for c in CALLS)
    return (
        type(ins).__name__,
        calls,
        tuple((a, outcome(getattr, ins, a)) for a in FIELDS),
        ("show_buff", outcome(ins.show_buff, 0)),
        ("get_output(5)", outcome(ins.get_output, 5)),
        ("str", outcome(str, ins)),
        ("get_operands()", outcome(ins.get_operands)),
    )


def flatten(shape: tuple) -> list:
    """insn_shape()'s tuple as a flat list of parts (for compact goldens)."""
    cls, calls, fields, *rest = shape
    return [cls, *calls, *fields, *rest]


def expand(indices, table) -> tuple:
    """Inverse of flatten() over a table of parts."""
    parts = [table[i] for i in indices]
    n, m = len(CALLS), len(FIELDS)
    return (parts[0], tuple(parts[1:1 + n]), tuple(parts[1 + n:1 + n + m]), *parts[1 + n + m:])


def method_shape(em) -> dict:
    """Everything observable through get_instructions(),
    get_instructions_idx() and get_instruction() of one method."""
    try:
        insns = list(em.get_instructions())
    except Exception as e:  # noqa: BLE001
        return {"error": (type(e).__name__, str(e))}
    # By equality: androguard's lookups return the listed objects
    # themselves (compared by identity); androguard_rs's return handles
    # equal to them.
    pos = {i: n for n, i in enumerate(insns)}

    def where(f, *args):
        try:
            v = f(*args)
        except Exception as e:  # noqa: BLE001
            return ("raise", type(e).__name__, str(e))
        return ("pos", pos.get(v, "foreign") if v is not None else None)

    offs = [off for off, _ in em.get_instructions_idx()]
    n = len(insns)
    lookups = []
    for k in range(n):
        lookups.append(where(em.get_instruction, k))
        lookups.append(where(em.get_instruction, 0, offs[k]))
    for extra in (n, -1, -n - 1):
        lookups.append(where(em.get_instruction, extra))
    for off in ((offs[-1] + 1) if offs else 1, 1, 10 ** 6):
        lookups.append(where(em.get_instruction, 0, off))
    again = list(em.get_instructions())
    return {
        "insns": [insn_shape(i) for i in insns],
        "offs": offs,
        "lookups": lookups,
        # asking again gives the same instructions (androguard: the same
        # objects; androguard_rs: equal handles with equal hashes)
        "same_objects": [a == b and hash(a) == hash(b) for a, b in zip(insns, again)] == [True] * n,
        "list_type": type(em.get_instructions()).__name__,
    }
