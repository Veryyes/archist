"""Tests for archist.extensions.lief using real ELF binaries."""

import pytest
import lief
import keystone
import capstone
import unicorn

from archist.extensions.lief import Ks, Cs, Uc


# ---- ARM (LE, ARM mode) ----


class TestARMElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "arm_le.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- ARM Thumb (LE) ----


class TestARMThumbElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "arm_thumb_le.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- AArch64 (LE) ----


class TestAArch64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "aarch64_le.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- MIPS32 (BE) ----


class TestMIPS32BEElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "mips32_be.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- MIPS32 (LE) ----


class TestMIPS32LEElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "mips32_le.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- MIPS64 (BE) ----


class TestMIPS64BEElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "mips64_be.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- PPC32 (BE) ----


class TestPPC32Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "ppc32_be.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- PPC64 (BE) ----


class TestPPC64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "ppc64_be.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- SPARC64 (BE) ----


class TestSPARC64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "sparc64_be.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- RISC-V 64 (LE) — no Ks support ----


class TestRISCV64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "riscv64_le.elf"))

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.binary)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- M68K (BE) — no Ks support ----


class TestM68KElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "m68k_be.elf"))

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.binary)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- SH4 (LE) — Cs only ----


class TestSH4Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "sh4_le.elf"))

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.binary)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Uc(self.binary)


# ---- S390X (BE) — Uc only ----


class TestS390XElf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "s390x_be.elf"))

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.binary)

    def test_cs_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Cs(self.binary)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- X86 32-bit (LE) ----


class TestX86_32Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "x86_32_le.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)


# ---- X86-64 (LE) ----


class TestX86_64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, elf_fixtures):
        self.binary = lief.ELF.parse(str(elf_fixtures / "x86_64_le.elf"))

    def test_ks(self):
        assert isinstance(Ks(self.binary), keystone.Ks)

    def test_cs(self):
        assert isinstance(Cs(self.binary), capstone.Cs)

    def test_uc(self):
        assert isinstance(Uc(self.binary), unicorn.Uc)
