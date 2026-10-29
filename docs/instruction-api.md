# Instruction API

Code written against androguard 4.1.3 walks instruction objects: names,
opcodes, operands, raw bytes, literal fields of the const formats,
positional and offset lookups. `androguard_rs.dex` provides androguard's
instruction classes under the same names, and the Analysis objects'
code objects return them with androguard 4.1.3's exact values.

## Import swap

```python
# from androguard.core.dex import Instruction, Instruction11n, Instruction21h, Instruction21s, Instruction31i, Instruction35c
from androguard_rs.core.dex import Instruction, Instruction11n, Instruction21h, Instruction21s, Instruction31i, Instruction35c
```

`isinstance` checks then hold for the objects the facade returns. Every
androguard 4.1.3 class for DEX bytecode is there (`Instruction10x` ...
`Instruction4rcc`, `Instruction00x`, the ODEX-only ones, `PackedSwitch`,
`SparseSwitch`, `FillArrayData`), plus `Kind`, `Operand`,
`DALVIK_OPCODES_FORMAT`, `DALVIK_OPCODES_PAYLOAD` and `InvalidInstruction`
(the same class as `androguard_rs.InvalidInstruction`).

## What serves it

| androguard | here |
|---|---|
| `EncodedMethod.get_instructions()` | facade `EncodedMethod.get_instructions()`: `[]` without code, else `get_code().get_bc().get_instructions()` (a generator) |
| `EncodedMethod.get_instructions_idx()` | generator of `(byte offset, instruction)` |
| `EncodedMethod.get_instruction(idx, off=None)` | `None` without code, else `DCode.get_instruction` |
| `get_code().get_bc()` (`DCode`) | `get_instructions()`, `get_instruction(idx, off)`, `off_to_pos()`, `get_ins_off()`, `get_raw()`, `get_length()`, `is_cached_instructions()` |
| `get_code().get_instruction(idx, off)` (`DalvikCode`) | same as `get_bc().get_instruction` |
| `Instruction.*` | `get_name`, `get_op_value`, `get_length`, `get_raw`, `get_hex`, `disasm`, `get_output(idx)`, `show_buff(idx)`, `show(idx)`, `__str__`, `get_operands(idx)`, `get_literals`, `get_kind`, `get_ref_kind`, `get_translated_kind`, `get_ref_off` (t formats), `get_string` (21c/31c); format fields (`A`, `B`, `AA`, `BBBB`, `BBBBBBBB`, `CCCC`, `NNNN`, ...) and `OP`, `length` |
| payloads | `get_name`, `get_op_value` (the ident), `get_length`, `get_raw`, `get_hex`, `disasm`, `get_output`, `get_operands`, `show_buff`, `get_keys`/`get_values`/`get_targets` (switches), `get_data` (fill-array-data), `add_note`/`get_notes`, `get_formatted_operands`; fields `ident`, `size`, `first_key`, `keys`, `targets`, `element_width`, `data`, `format_general_size`, `OP` |

A method's instruction objects are handles made natively for each query
(`core/src/insn_rows.rs`: `insn_spans()` finds the boundaries and opcodes
with the decoder's own validity checks, without formatting text): two slots
each (the method's insns and the byte offset; the opcode is the byte
there), untracked by the cycle collector, offsets shared int objects.
Nothing is kept per method on the Python side: `get_instructions()` asked
twice makes new objects that compare and hash equal to the first ones (an
instruction is its method's code and offset), not the same objects, as
androguard's cached list gives (an intentional difference, as is that a
payload's `add_note()` notes stay on that one object).
`get_instruction(idx)` / `get_instruction(0, off)` make only the one
instruction asked for; the boundaries of the last 32 methods asked for are
kept natively, so stepping through a method instruction by instruction
decodes it once. The text (`get_output()`, the resolved reference) is
decoded natively for one instruction when asked for, as androguard formats
it on every call. Format fields are unpacked from the instruction's own
bytes on first access, with the struct formats androguard's constructors
use. (`androguard_rs.Apk.instructions(key)` still returns one method's
`(insns_bytes, rows)`, each row `(offset, op_value, length, raw_len,
get_output(), resolved reference or None)`.)

## androguard quirks reproduced

- `Instruction21h.BBBB` is the shifted value (`<< 16` for const/high16,
  `<< 48` for const-wide/high16); the raw 16 bits are `_Instruction21h__BBBB`.
- `Instruction11n.B`, 21s, 21t, 22s, 22t, 22b, 10t, 20t, 30t, 31i, 31t, 51l
  values are signed. 31c's index is a signed int too: const-string/jumbo
  with an index of 2**31 or more resolves through Python's negative list
  indexing (0xFFFFFFFF is the DEX's last string) and its `get_raw()` raises
  `struct.error`. The native renderer resolves it the same way, so
  `get_output()`/`bytecode()` text matches.
- `get_translated_kind()` raises `IndexError` for opcodes without a kind,
  `Exception("not implemented")` for invoke-polymorphic(/range), and returns
  `None` for invoke-custom(/range) and const-method-type.
  const-method-handle resolves its index as a method. Payloads have no
  `get_translated_kind()`/`get_kind()`/`get_literals()` (AttributeError).
- `get_operands()`: kind entries are `(Kind + Operand.KIND, index, text)`
  with a plain int first; 35c with more than 5 registers gives `[]`;
  3rc with a count of 0 gives just the kind; 45cc/4rcc's `get_operands()`
  takes no argument and returns `None`; fill-array-data gives
  `[(Operand.RAW, repr(data))]`.
- 45cc with no registers: `get_output()` is `None`; 35c with more than 5:
  `""`.
- Payloads: `get_op_value()` is the ident (0x100/0x200/0x300) while `OP` is
  0. A packed-switch whose size overruns the method reads fewer targets
  (`len(buff) - 16`), so its `get_raw()` is shorter than `get_length()`; a
  fill-array-data cut short keeps the bytes that are there. Either ends the
  sweep.
- `get_instruction(idx)` indexes the cached list (negative indices count
  from the end, out of range is IndexError). `get_instruction(idx, off)`
  ignores `idx`; an `off` that isn't an instruction boundary gives position
  -1, i.e. the last instruction.

## Deliberate differences

- androguard_rs models androguard after `AnalyzeAPK`/`create_xref()`: every method is disassembled and cached, so
  `get_instruction(idx)` works without iterating first. Plain androguard
  without `create_xref()` raises `TypeError` there until something
  iterates the method. A method androguard can't disassemble makes
  `Analysis.add()` fail; so do `androguard_rs.misc.AnalyzeAPK` and
  `androguard_rs.analysis.Analysis.add()`, with the same exception, type,
  args and `str()` included. Loaded with
  `tolerant=True`, only that method raises `InvalidInstruction`, on the
  first `next()` of `get_instructions()` or on `get_instruction()`.
- `repr()`/`str()` of a payload (androguard has no `__str__` there) shows
  `androguard_rs.dex` and another address; androguard's address differs on
  every run anyway.
- `ins.cm` and `get_raw_string()` need androguard's ClassManager: they
  raise `NotImplementedError`, counted in `androguard_rs.dex.GAPS`.
- A method whose code_item another method shares (crafted files) shares
  its instruction objects (androguard makes a list per method).

## Parity and tests

- `python/tests/test_insn.py` (no androguard): `insn_apk.py`'s synthetic
  DEX holds every opcode androguard decodes, 35c with 0-7 registers, 3rc
  with 0/1/255, 45cc with 0-5, 4rcc, literal extremes of every const form,
  out-of-range and negative references, all payloads (truncated too),
  empty and abstract methods, and the 9 kinds of bytecode androguard
  rejects. Everything `insn_shapes.method_shape()` observes is compared
  with goldens from androguard 4.1.3 (`insn_goldens.py`, regenerated by
  `scripts/gen_insn_goldens.py`).
- `python/tests/test_insn_parity.py` (`PARITY_APKS`): the same comparison,
  live against `AnalyzeAPK`, for every method of every defined class.
- `core/src/insn_rows.rs` unit tests; the `decode` fuzz target checks the
  rows against both decoders, and `dex_pipeline` runs them on every method.
