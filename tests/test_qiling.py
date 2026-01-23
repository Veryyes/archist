"""Tests for qiling emulator basic usage."""

from qiling import Qiling
from qiling.const import QL_OS

from archist import X86, X8664

def test_shellcode_emulation() -> None:
    """Test emulating x86 shellcode."""
    # XOR EAX, EAX; INC EAX; NOP
    shellcode = b"\x31\xc0\x40\x90"

    ql = Qiling(
        code=shellcode,
        archtype=X86.ql,
        ostype=QL_OS.LINUX,
        rootfs="/",
    )
    ql.run()

    assert ql.arch.regs.eax == 1


def test_shellcode_x64() -> None:
    """Test emulating x86_64 shellcode."""
    # XOR RAX, RAX; INC RAX; INC RAX
    shellcode = b"\x48\x31\xc0\x48\xff\xc0\x48\xff\xc0"

    ql = Qiling(
        code=shellcode,
        archtype=X8664.ql,
        ostype=QL_OS.LINUX,
        rootfs="/",
    )
    ql.run()

    assert ql.arch.regs.rax == 2
