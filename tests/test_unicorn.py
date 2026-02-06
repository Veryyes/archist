"""Tests for unicorn-engine basic usage."""

from unicorn import Uc

from archist import X86


def test_emulate_x86_inc() -> None:
    """Test emulating x86 INC instruction."""
    # INC ECX (0x41)
    code = b"\x41"

    uc = Uc(X86.uc, X86.mode._32.uc)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_write(0x1000, code)
    uc.reg_write(X86.reg.ecx, 0x1234)

    uc.emu_start(0x1000, 0x1000 + len(code))

    assert uc.reg_read(X86.reg.ecx) == 0x1235


def test_emulate_x86_add() -> None:
    """Test emulating x86 ADD instruction."""
    # ADD EAX, ECX
    code = b"\x01\xc8"

    uc = Uc(X86.uc, X86.mode._32.uc)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_write(0x1000, code)
    uc.reg_write(X86.reg.eax, 1)
    uc.reg_write(X86.reg.ecx, 2)

    uc.emu_start(0x1000, 0x1000 + len(code))

    assert uc.reg_read(X86.reg.eax) == 3
