"""Tests for archist.extensions.pyelftools using real ELF binaries."""

import pytest
import keystone
import capstone
import unicorn
from elftools.elf.elffile import ELFFile

from archist.extensions.pyelftools import Ks, Cs, Uc


def _open_elf(path):
    return ELFFile(open(path, "rb"))


# ---- ARM (LE, ARM mode) ----


class TestARMElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "arm_le.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_ARM
        assert ks._mode == keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_ARM
        assert cs.mode == capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_ARM
        assert uc._mode == unicorn.UC_MODE_ARM | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- ARM Thumb (LE) ----


class TestARMThumbElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "arm_thumb_le.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_ARM
        assert ks._mode == keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_ARM
        assert cs.mode == capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_ARM
        assert uc._mode == unicorn.UC_MODE_THUMB | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- AArch64 (LE) ----


class TestAArch64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "aarch64_le.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_ARM64
        assert ks._mode == keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_ARM64
        assert cs.mode == capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_ARM64
        assert uc._mode == unicorn.UC_MODE_LITTLE_ENDIAN


# ---- MIPS32 (BE) ----


class TestMIPS32BEElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "mips32_be.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS32 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN


# ---- MIPS32 (LE) ----


class TestMIPS32LEElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "mips32_le.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS32 | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- MIPS64 (BE) ----


class TestMIPS64BEElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "mips64_be.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- PPC32 (BE) ----


class TestPPC32Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "ppc32_be.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_PPC
        assert ks._mode == keystone.KS_MODE_PPC32 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_PPC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_PPC
        assert uc._mode == unicorn.UC_MODE_PPC32 | unicorn.UC_MODE_BIG_ENDIAN


# ---- PPC64 (BE) ----


class TestPPC64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "ppc64_be.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_PPC
        assert ks._mode == keystone.KS_MODE_PPC64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_PPC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_PPC
        assert uc._mode == unicorn.UC_MODE_PPC64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- SPARC64 (BE) ----


class TestSPARC64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "sparc64_be.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_SPARC
        assert ks._mode == keystone.KS_MODE_SPARC64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_SPARC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_SPARC
        assert uc._mode == unicorn.UC_MODE_SPARC64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- RISC-V 64 (LE) — no Ks support ----


class TestRISCV64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "riscv64_le.elf")

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.elf)

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_RISCV
        assert cs.mode == capstone.CS_MODE_RISCV64 | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_RISCV
        assert uc._mode == unicorn.UC_MODE_RISCV64 | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- M68K (BE) — no Ks support ----


class TestM68KElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "m68k_be.elf")

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.elf)

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_M68K
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_M68K
        assert uc._mode == unicorn.UC_MODE_BIG_ENDIAN


# ---- SH4 (LE) — Cs only ----


class TestSH4Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "sh4_le.elf")

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.elf)

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_SH
        assert cs.mode == capstone.CS_MODE_SH4 | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Uc(self.elf)


# ---- S390X (BE) — Uc only ----


class TestS390XElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "s390x_be.elf")

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.elf)

    def test_cs_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Cs(self.elf)

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_S390X
        assert uc._mode == unicorn.UC_MODE_BIG_ENDIAN


# ---- X86 32-bit (LE) ----


class TestX86_32Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "x86_32_le.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_X86
        assert ks._mode == keystone.KS_MODE_32

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_X86
        assert cs.mode == capstone.CS_MODE_32

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_X86
        assert uc._mode == unicorn.UC_MODE_32


# ---- X86-64 (LE) ----


class TestX86_64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.elf = _open_elf(elf_fixtures / "x86_64_le.elf")

    def test_ks(self):
        ks = Ks(self.elf)
        assert ks._arch == keystone.KS_ARCH_X86
        assert ks._mode == keystone.KS_MODE_64

    def test_cs(self):
        cs = Cs(self.elf)
        assert cs.arch == capstone.CS_ARCH_X86
        assert cs.mode == capstone.CS_MODE_64

    def test_uc(self):
        uc = Uc(self.elf)
        assert uc._arch == unicorn.UC_ARCH_X86
        assert uc._mode == unicorn.UC_MODE_64
