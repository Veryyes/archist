"""Tests for capstone-engine basic usage."""

from archist import X86


def test_disassemble_x86_32() -> None:
    """Test disassembling x86 32-bit code."""
    # INC ECX; DEC EDX
    code = b"\x41\x4a"

    md = X86.Cs(mode=32)
    instructions = list(md.disasm(code, 0x1000))

    assert len(instructions) == 2
    assert instructions[0].mnemonic == "inc"
    assert instructions[0].op_str == "ecx"
    assert instructions[1].mnemonic == "dec"
    assert instructions[1].op_str == "edx"


def test_disassemble_x86_64() -> None:
    """Test disassembling x86 64-bit code."""
    # NOP; RET
    code = b"\x90\xc3"

    md = X86.Cs(mode=64)
    instructions = list(md.disasm(code, 0x1000))

    assert len(instructions) == 2
    assert instructions[0].mnemonic == "nop"
    assert instructions[1].mnemonic == "ret"
