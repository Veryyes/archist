"""Tests for keystone-engine basic usage."""

from keystone import Ks, KS_MODE_32, KS_MODE_64

from archist import X86, X8664


def test_assemble_x86_32() -> None:
    """Test assembling x86 32-bit code."""
    ks = Ks(X86.ks, KS_MODE_32)
    encoding, count = ks.asm("INC ECX; DEC EDX")

    assert encoding is not None
    assert bytes(encoding) == b"\x41\x4a"
    assert count == 2


def test_assemble_x86_64() -> None:
    """Test assembling x86 64-bit code."""
    ks = Ks(X8664.ks, KS_MODE_64)
    encoding, count = ks.asm("NOP; RET")

    assert encoding is not None
    assert bytes(encoding) == b"\x90\xc3"
    assert count == 2


def test_assemble_mov() -> None:
    """Test assembling MOV instruction."""
    ks = Ks(X86.ks, KS_MODE_32)
    encoding, count = ks.asm("MOV EAX, 0x1234")

    assert encoding is not None
    assert count == 1
    assert bytes(encoding) == b"\xb8\x34\x12\x00\x00"
