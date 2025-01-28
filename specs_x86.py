#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
specs_x86.py

Provides functions to disassemble x86-64 binaries using Capstone, parse registers used,
and gather instruction statistics. The main entry points are `analyze_binary` (returns
a BinarySpecs object) and `yield_instructions_from_binary` (yields InstructionSpecs
for each instruction).
"""

import os
from typing import Generator, Dict
import mmap

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from specs import InstructionSpecs, BinarySpecs

#: Constant mapping of register names to their sizes in bits.
REGISTER_TO_SIZE: Dict[str, int] = {}


def _init_register_to_size() -> Dict[str, int]:
    """
    Initializes a dictionary mapping AArch64 register names to their size in bits.
    Includes:
    - General-purpose: rax..r15 (64 bits), eax..r15d (32 bits), ax..r15w (16 bits), al..r15b (8 bits)
    - 16x 128-bit SIMD for SSE: xmm0..xmm15
    - 16x 256-bit SIMD for AVX: ymm0..ymm15
    - 32x 512-bit SIMD for AVX-512: zmm0..zmm31
    - 8x 64-bit predicate registers for AVX-512: k0..k7

    References:
    https://en.wikipedia.org/wiki/Advanced_Vector_Extensions
    https://en.wikibooks.org/wiki/X86_Assembly/16,_32,_and_64_Bits
    """
    # TODO: Add TMM registers for AMX instructions
    # TODO: Add K registers for AVX-512
    mapping: Dict[str, int] = {}
    # 512-bit
    for i in range(32):
        mapping[f"zmm{i}"] = 512
    # 256-bit
    for i in range(16):
        mapping[f"ymm{i}"] = 256
    # 128-bit
    for i in range(16):
        mapping[f"xmm{i}"] = 128

    # 64-bit
    for i in range(8, 16):
        mapping[f"r{i}"] = 64

    # Named 64-bit registers
    for reg in [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsp",
        "rbp",
        "rsi",
        "rdi",
        "rip",
    ]:
        mapping[reg] = 64

    # Named 32-bit registers
    for reg in [
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esp",
        "ebp",
        "esi",
        "edi",
        "eip",
        "eflags",
    ]:
        mapping[reg] = 32

    # Named 16-bit registers
    for reg in [
        "ax",
        "bx",
        "cx",
        "dx",
        "sp",
        "bp",
        "si",
        "di",
        "cs",
        "ss",
        "es",
        "ds",
        "ip",
        "flags",
    ]:
        mapping[reg] = 16

    # 8-bit
    for reg in ["ah", "al", "bh", "bl", "ch", "cl", "dh", "dl"]:
        mapping[reg] = 8

    return mapping


# Populate it at import
REGISTER_TO_SIZE = _init_register_to_size()


def parse_instruction(cs_instr) -> InstructionSpecs:
    """
    Parses a single Capstone instruction into an InstructionSpecs object,
    determining the largest register size involved.
    """
    instr_specs = InstructionSpecs()
    instr_specs.mnemonic = cs_instr.mnemonic

    for op in cs_instr.operands:
        if op.type == 1:  # capstone.CS_OP_REG
            reg_name = cs_instr.reg_name(op.reg)
            # Convert to lowercase to match dictionary keys, if necessary
            reg_name = reg_name.lower()
            reg_size = REGISTER_TO_SIZE.get(reg_name, 0)
            if reg_size > instr_specs.register_size:
                instr_specs.register_size = reg_size

    return instr_specs


def yield_instructions_from_binary(
    path: str,
) -> Generator[InstructionSpecs, None, None]:
    """
    Disassembles the binary at `path` in 64-bit mode using Capstone,
    yielding an InstructionSpecs object for each instruction found.
    """
    if not os.path.isfile(path):
        return  # Could raise an exception or log warning instead

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True

    with open(path, mode="rb") as f:
        # Memory-map approach for large files instead of reading all at once
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for cs_instr in md.disasm(mm, 0):
                yield parse_instruction(cs_instr)


def analyze_binary(path: str) -> BinarySpecs:
    """
    Analyzes the x86-64 instructions in `path`,
    returning a BinarySpecs object with instruction frequencies
    and register size frequencies.
    """
    ret = BinarySpecs(path=path)
    for instr_specs in yield_instructions_from_binary(path):
        instr_name = instr_specs.name
        ret.code_frequencies[instr_name] = ret.code_frequencies.get(instr_name, 0) + 1
        key_size = instr_specs.register_size
        ret.size_frequencies[key_size] = ret.size_frequencies.get(key_size, 0) + 1

    return ret
