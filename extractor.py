#!/usr/bin/env python3
"""
extractor.py                     –  Binary Ninja script to extract amos stealer bash files for analyzing and mitigation
this script can take the whole binary and output the bash scripts.

Run:
    python grab_arrays.py malware
"""

from pathlib import Path
import sys
# Binary Ninja API
#
# Upstream recently replaced the long-standing helper
# ``BinaryViewType.get_view_of_file`` with :pyfunc:`binaryninja.load`.
# Import the full *binaryninja* module in addition to the symbols we
# explicitly use so that we can rely on the stable ``load`` helper for
# opening a file.  This keeps the rest of the script untouched.

# Binary Ninja API ---------------------------------------------------------
#
# Binary Ninja's IL operation enumerations have changed a bit over time. In
# particular, what were once `MLIL_FOR`/`MLIL_WHILE` loop operations now live
# in the HLIL name-space (`HLIL_FOR`/`HLIL_WHILE`) and the legacy helper
# `BinaryViewType.get_view_of_file` has been replaced by `binaryninja.load`.
#
# To keep the script working across both old and new releases we import *both*
# Medium- and High-level IL enumerations and build a couple of small helper
# sets that cover the operation codes we are interested in.  The rest of the
# script then simply checks membership in those sets instead of hard-coding a
# single enum value.

import binaryninja as bn
from binaryninja import (
    BinaryViewType,  # for backwards compatibility fall-back
    MediumLevelILOperation as MLOp,
    HighLevelILOperation as HLOp,
    log_info,
    log_warn,
)

# Backwards-compatibility alias ------------------------------------------------
#
# The original script imported ``MediumLevelILOperation`` as *Op*.  To avoid a
# sweeping refactor we keep that name but point it at the HLIL enum which
# contains the loop constructs we care about in modern Binary Ninja builds.

Op = HLOp

# Friendly aliases covering both IL generations --------------------------------

# Loop headers
LOOP_FOR_OPS = set()
for name in ("MLIL_FOR", "HLIL_FOR"):
    LOOP_FOR_OPS.add(getattr(MLOp, name, None))
    LOOP_FOR_OPS.add(getattr(HLOp, name, None))
LOOP_FOR_OPS.discard(None)

LOOP_WHILE_OPS = set()
for name in ("MLIL_WHILE", "HLIL_WHILE"):
    LOOP_WHILE_OPS.add(getattr(MLOp, name, None))
    LOOP_WHILE_OPS.add(getattr(HLOp, name, None))
LOOP_WHILE_OPS.discard(None)

# Arithmetic ADD (pointer arithmetic)
ADD_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_ADD", None),
        getattr(HLOp, "HLIL_ADD", None),
    )
    if op is not None
}

# Constant pointer literal
CONST_PTR_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_CONST_PTR", None),
        getattr(HLOp, "HLIL_CONST_PTR", None),
    )
    if op is not None
}

# Memory load / dereference
LOAD_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_LOAD", None),
        getattr(HLOp, "HLIL_DEREF", None),  # HLIL renamed LOAD -> DEREF
    )
    if op is not None
}


# ---------------------------------------------------------------------------
#  helpers
# ---------------------------------------------------------------------------

def const_ptr(expr):
    """
    If  ‹expr› is ADD( VAR, CONST_PTR  )   or   ADD( CONST_PTR, VAR )
    return that CONST_PTR.  Otherwise  None.
    """
    if expr.operation not in ADD_OPS:
        return None

    for side in (expr.left, expr.right):
        if side.operation in CONST_PTR_OPS:
            return side.constant
    return None


def base_of_load(expr):
    """
    Recursively look for a memory dereference (``LOAD``/``DEREF``) wrapped in
    casts or bit-extraction helpers and return the constant base address inside
    its pointer arithmetic.
    """
    # Only High/Medium-level IL expressions have an ``operation`` attribute.
    if not hasattr(expr, "operation"):
        return None

    # Direct dereference → examine its source pointer arithmetic.
    if expr.operation in LOAD_OPS:
        return const_ptr(expr.src)

    # Unwrap common single-operand wrappers (LOW_PART, SIGN/ZERO-EXTEND, etc.).
    single_operand_attrs = ("src", "operand", "value")
    for attr in single_operand_attrs:
        inner = getattr(expr, attr, None)
        if inner is not None:
            base = base_of_load(inner)
            if base:
                return base

    # Fall back to brute-force traversing child operands provided by the API.
    for op in getattr(expr, "operands", []):
        base = base_of_load(op)
        if base:
            return base

    # No constant base found
    return None


def extract_arrays(bv):
    """
    Returns  [(base_addr, length), …]  in the order they appear in _start.
    """

    fn = bv.get_function_at(bv.entry_point)   # ==  _start
    arrays = []

    # DEBUG
    # print("Analyzing function", fn)

    #
    # 1.  Walk HLIL “for” / “while” constructs.
    #
    for inst in fn.hlil.instructions:

        if inst.operation not in (LOOP_FOR_OPS | LOOP_WHILE_OPS):
            continue

        #
        #  – length  =  upper_bound  (must be constant)      («i != 0x200»)
        #  – stride   is always +4                           («i += 4»)
        #
        guard = inst.condition
        # Expect a comparison against the loop bound. Works for both MLIL and
        # HLIL depending on the Binary Ninja version in use.
        if guard.operation not in {
            getattr(MLOp, "MLIL_CMP_NE", None),
            getattr(HLOp, "HLIL_CMP_NE", None),
        }:
            continue
        limit_expr = guard.right
        if limit_expr.operation not in {
            getattr(MLOp, "MLIL_CONST", None),
            getattr(HLOp, "HLIL_CONST", None),
        }:
            continue

        length = limit_expr.constant          # e.g. 0x200

        #
        # 2.  Walk the loop body and collect every LOAD that is part of a
        #     SUB / XOR chain.  All three bases appear in a single statement.
        #
        def collect_bases(expr):
            """Recursively walk *expr* and collect every constant base address.

            We do **not** stop at the first hit because a compound expression
            like ``(LOAD(a) - LOAD(b)) ^ LOAD(c)`` contains three distinct
            arrays that all need to be recorded.
            """
            if hasattr(expr, "operation") and expr.operation in LOAD_OPS:
                base = const_ptr(expr.src)
                if base:
                    found.add(base)
            # Recurse into child operands
            for opnd in getattr(expr, "operands", []):
                collect_bases(opnd)

        for body_stmt in inst.body:
            if body_stmt.operation not in {
                getattr(MLOp, "MLIL_XOR", None),
                getattr(HLOp, "HLIL_XOR", None),
                getattr(MLOp, "MLIL_SUB", None),
                getattr(HLOp, "HLIL_SUB", None),
            }:
                continue

            found: set[int] = set()
            collect_bases(body_stmt)
            for base in sorted(found):
                arrays.append((base, length))

        # Done – this loop has been handled.

    return arrays


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> None:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <binary>", file=sys.stderr)
        sys.exit(1)

    # Binary Ninja 4.2 deprecated ``BinaryViewType.get_view_of_file`` in
    # favour of the higher-level ``binaryninja.load`` convenience helper.
    #
    # Use it here so the script works with both new and old releases.  For
    # older versions we fall back to the previous API if it's still
    # available.

    try:
        bv = bn.load(argv[1])  # already waits for analysis by default
    except AttributeError:
        # Very old Binary Ninja builds (<4.2) – keep existing behaviour.
        bv = BinaryViewType.get_view_of_file(argv[1])
        bv.update_analysis_and_wait()

    array_meta = extract_arrays(bv)

    if len(array_meta) < 3:
        log_warn(
            f"Only found {len(array_meta)} constant arrays – continuing without extraction."
        )
        # Continue execution instead of bailing out.  A mismatch here is not a
        # fatal error for the purpose of simply *loading* the binary.
        return

    # ------------------------------------------------------------------
    # Stage-1  –  dump the three raw constant buffers of the *first* group
    #            (handy for debugging/verification).
    # ------------------------------------------------------------------

    filenames = ["base.bin", "sub.bin", "xor.bin"]
    for (addr, length), outname in zip(array_meta[:3], filenames):
        Path(outname).write_bytes(bv.read(addr, length))
        log_info(f"Wrote {length:#x} bytes from 0x{addr:x} -> {outname}")

    # ------------------------------------------------------------------
    # Stage-2  –  reconstruct the strings the malware builds at run-time.
    # ------------------------------------------------------------------

    def lowbyte_decode(base_bytes: bytes, xor_bytes: bytes, sub_bytes: bytes) -> bytes:
        """Return the raw bytes produced by the low-byte arithmetic."""
        #swapped base_bytes and xor_bytes because the extractor got confused.  array 0 = base, array 2 = xor array 3 = sub. 
        if not (len(base_bytes) == len(sub_bytes) == len(xor_bytes)):
            raise ValueError("buffers must have equal length")
        if len(base_bytes) % 4:
            raise ValueError("length must be a multiple of 4")
        base_bytes = list(base_bytes)
        sub_bytes = list(sub_bytes)
        xor_bytes = list(xor_bytes)
        out = bytearray()
        for i in range(0, len(base_bytes), 4):
            b = base_bytes[i]
            s = sub_bytes[i]
            x = xor_bytes[i]
            out.append(((b -s) & 0xff)  ^x)
        return bytes(out)

    def triplet_to_hex_string(base_bytes: bytes, sub_bytes: bytes, xor_bytes: bytes) -> str:
        """Return the ASCII *hex* string produced by the low-byte expression.

        Mirrors exactly what the malware loop does: one byte per 32-bit word
        taking only the least-significant byte of each buffer.
        """
        if not (len(base_bytes) == len(sub_bytes) == len(xor_bytes)):
            raise ValueError("buffers must have equal length")
        if len(base_bytes) % 4:
            raise ValueError("length must be a multiple of 4")

        raw = lowbyte_decode(base_bytes, sub_bytes, xor_bytes)
        return raw.decode("latin1", "strict")

    def hex_string_to_bytes(hex_str: str) -> bytes:
        outtransformed = bytearray()
        for i in range(0, len(hex_str)-1 , 2): #pull pairs of chars
            outtransformed.append(int(hex_str[i] + hex_str[i+1], 16))

        return bytes(outtransformed)
    # The first triplet contains 128 characters – each of the 64 symbols twice
    # – which forms the malware's custom *base-64* alphabet.
    if len(array_meta) < 3:
        log_warn("Did not find enough arrays for alphabet extraction – skipping stage-2 decoding")
        return

    base0, ln0 = array_meta[0]
    sub0, _ = array_meta[1]
    xor0, _ = array_meta[2]

    alphabet_raw = triplet_to_hex_string(
        bv.read(base0, ln0),
        bv.read(sub0, ln0),
        bv.read(xor0, ln0),
    )
    
    seen = set()
    alphabet = hex_string_to_bytes(alphabet_raw)
    print(f"Custom alphabet: {alphabet!r}")
    if len(alphabet) != 64:
        log_warn(
            f"Expected 64 distinct characters for custom alphabet, got {len(alphabet)} – skipping decoding"
        )
        return

    print(f"Custom alphabet: {alphabet!r}")

    # Mapping char -> 6-bit value
    b64_map = {ch: idx for idx, ch in enumerate(alphabet.decode('latin1'))}

    def custom_b64_decode(data: str) -> bytes:
        bits = 0
        nbits = 0
        out = bytearray()
        for ch in data:
            val = b64_map.get(ch)
            if val is None:
                continue  # ignore padding / unexpected chars
            bits = (bits << 6) | val
            nbits += 6
            while nbits >= 8:
                nbits -= 8
                out.append((bits >> nbits) & 0xFF)
        return bytes(out)

    # Process every remaining triplet and drop the decoded payload to disk.
    file_index = 0
    for grp in range(1, len(array_meta) // 3):
        base_addr, length = array_meta[grp * 3]
        sub_addr, _ = array_meta[grp * 3 + 1]
        xor_addr, _ = array_meta[grp * 3 + 2]

        hex_string = triplet_to_hex_string(
            bv.read(base_addr, length),
            bv.read(sub_addr, length),
            bv.read(xor_addr, length),
        )

        encoded_bytes = hex_string_to_bytes(hex_string)
        encoded_str = encoded_bytes.decode("latin1", "ignore")

        plaintext = custom_b64_decode(encoded_str)
        print(plaintext)
        outpath = Path(f"out_{file_index}.txt")
        outpath.write_bytes(plaintext)
        log_info(f"Decoded payload #{file_index} – {len(plaintext)} bytes -> {outpath}")

        file_index += 1


if __name__ == "__main__":
    main(sys.argv)
