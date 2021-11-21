import string
from typing import Generator

from capstone import *

from specs import *

# https://en.wikipedia.org/wiki/Advanced_Vector_Extensions
# https://en.wikibooks.org/wiki/X86_Assembly/16,_32,_and_64_Bits

_register_to_size = {}


def get_register_to_size() -> Dict[str, int]:
    global _register_to_size
    if len(_register_to_size):
        return _register_to_size

    for x in ['zmm' + str(i) for i in range(0, 32)]:
        _register_to_size[x] = 512
    for x in ['ymm' + str(i) for i in range(0, 32)]:
        _register_to_size[x] = 256
    for x in ['xmm' + str(i) for i in range(0, 32)]:
        _register_to_size[x] = 128

    for x in ['rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rsi', 'rdi', 'rip']:
        _register_to_size[x] = 64
    for x in ['r' + str(i) for i in range(8, 16)]:
        _register_to_size[x] = 64

    for x in ['eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi', 'eip', 'eflags']:
        _register_to_size[x] = 32
    for x in ['ax', 'bx', 'cx', 'dx', 'sp', 'bp', 'si', 'di', 'cs', 'ss', 'es', 'ds', 'ip', 'flags']:
        _register_to_size[x] = 16
    for x in ['ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']:
        _register_to_size[x] = 8

    return _register_to_size


def tokenize_instructions_line(op_str: str):
    current_word = ''
    banned_chars = string.punctuation + ' '
    for c in op_str:
        if c in banned_chars:
            if len(current_word):
                yield current_word
                current_word = ''
        else:
            current_word += c
    if len(current_word):
        yield current_word


def parse_instruction(i) -> InstructionSpecs:
    size_resolver = get_register_to_size()
    ret = InstructionSpecs()
    ret.mnemonic = i.mnemonic
    for word in tokenize_instructions_line(i.op_str):
        word_size = size_resolver.get(word, 0)
        ret.register_size = max(ret.register_size, word_size)
    return ret


def yield_instructions_from_binary(path: str) -> Generator[InstructionSpecs, None, None]:

    with open(path, mode='rb') as file:
        code = file.read()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.skipdata = True
        for instruction in md.disasm(code, 0):
            yield parse_instruction(instruction)


def analyze_binary(path: str) -> BinarySpecs:
    ret = BinarySpecs(path=path)

    for i in yield_instructions_from_binary(path):
        name = i.name
        ret.code_frequencies[name] = ret.code_frequencies.get(name, 0) + 1
        ret.size_frequencies[i.register_size] = ret.size_frequencies.get(
            i.register_size, 0) + 1

    return ret
