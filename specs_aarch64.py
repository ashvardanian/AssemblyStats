#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
specs_aarch64.py

Provides functions to disassemble AArch64 (ARMv8+) binaries using Capstone, parse registers used,
and gather instruction statistics. The main entry points are `analyze_binary` (returns
a BinarySpecs object) and `yield_instructions_from_binary` (yields InstructionSpecs
for each instruction).
"""

import os
from typing import Generator, Dict
import mmap

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from specs import InstructionSpecs, BinarySpecs

#: A dictionary mapping register names to their sizes (in bits).
REGISTER_TO_SIZE: Dict[str, int] = {}
MAX_SVE_SIZE = 2048


def _init_register_to_size() -> Dict[str, int]:
    """
    Initializes a dictionary mapping AArch64 register names to their size in bits.
    Includes:
    - General-purpose: x0..x30 (64 bits), w0..w30 (32 bits)
    - NEON: v0..v31 (128 bits)
    - SVE: z0..z31, p0..p15 (using 2048 bits for z, and 256 or 2048 for p—pick a policy)
    - SME: t0..t31 if desired (2048 bits, or some 'max' size)
    """
    mapping: Dict[str, int] = {}

    # General-purpose registers
    for i in range(31):
        mapping[f"x{i}"] = 64
        mapping[f"w{i}"] = 32
    # x30 is usually LR, but still 64 bits in AArch64

    # NEON / FP registers (v0..v31) - typically 128 bits
    for i in range(32):
        mapping[f"v{i}"] = 128

    # SVE registers (scalable). We'll assume "max" size of 2048 bits for z-regs.
    # Predicates p0..p15 are also scalable, but let's pick 256 bits or 2048 bits.
    # This is purely a policy decision to reflect maximum vector usage.
    for i in range(32):
        mapping[f"z{i}"] = MAX_SVE_SIZE
    for i in range(16):
        mapping[f"p{i}"] = MAX_SVE_SIZE  # or 256 if you prefer a "typical" size

    # SME tile registers (Armv9.2+). The architecture supports 128, 256, 512, 1024, or 2048 bits.
    # We'll assign 2048 bits to represent the largest usage scenario.
    for i in range(32):
        mapping[f"t{i}"] = MAX_SVE_SIZE

    # Some special registers: sp (stack pointer), pc (if Capstone exposes it),
    # or system registers. We can add them as needed. E.g.:
    mapping["sp"] = 64
    # AArch64 doesn't generally expose 'pc' as a normal register in user space.

    return mapping


# Populate REGISTER_TO_SIZE at module import
REGISTER_TO_SIZE = _init_register_to_size()


def parse_instruction(cs_instr) -> InstructionSpecs:
    """
    Parses a single Capstone instruction into an InstructionSpecs object,
    determining the largest register size involved based on REGISTER_TO_SIZE.
    """
    instr_specs = InstructionSpecs()
    instr_specs.mnemonic = cs_instr.mnemonic

    for op in cs_instr.operands:
        # Capstone for ARM64: op.type == 1 means register operand
        if op.type == 1:  # capstone.CS_OP_REG
            reg_name = cs_instr.reg_name(op.reg)
            # Convert to lowercase (some versions of Capstone might return uppercase)
            reg_name = reg_name.lower()
            # Look up size in our mapping
            reg_size = REGISTER_TO_SIZE.get(reg_name, 0)
            if reg_size > instr_specs.register_size:
                instr_specs.register_size = reg_size

    return instr_specs


def yield_instructions_from_binary(
    path: str,
) -> Generator[InstructionSpecs, None, None]:
    """
    Disassembles the binary at `path` in AArch64 mode using Capstone,
    yielding an InstructionSpecs object for each instruction found.
    """
    if not os.path.isfile(path):
        return  # or raise an exception

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    md.skipdata = True

    with open(path, mode="rb") as f:
        # Memory-map approach for large files instead of reading all at once
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for cs_instr in md.disasm(mm, 0):
                yield parse_instruction(cs_instr)


def analyze_binary(path: str) -> BinarySpecs:
    """
    Analyzes the AArch64 instructions in `path`,
    returning a BinarySpecs object with instruction frequencies
    and register-size frequencies.
    """
    ret = BinarySpecs(path=path)
    for instr_specs in yield_instructions_from_binary(path):
        instr_name = instr_specs.name
        ret.code_frequencies[instr_name] = ret.code_frequencies.get(instr_name, 0) + 1
        key_size = instr_specs.register_size
        ret.size_frequencies[key_size] = ret.size_frequencies.get(key_size, 0) + 1

    return ret
