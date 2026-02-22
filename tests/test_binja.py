"""Tests for archist.extensions.binja using real ELF binaries loaded via Binary Ninja."""

import pytest
import keystone
import capstone
import unicorn

from archist.extensions.binja import Ks, Cs, Uc

binaryninja = pytest.importorskip("binaryninja")

# NOTE
# SPARC, MK86, SH4, S390X are all not supported by binary ninja


@pytest.fixture(scope="session")
def binja_bvs(elf_fixtures):
    """Load all ELF fixtures into Binary Ninja BinaryViews once per session."""
    elf_names = [
        "arm_le.elf",
        "arm_thumb_le.elf",
        "aarch64_le.elf",
        "mips32_be.elf",
        "mips32_le.elf",
        "mips64_be.elf",
        "ppc32_be.elf",
        "ppc64_be.elf",
        "riscv64_le.elf",
        "x86_32_le.elf",
        "x86_64_le.elf",
    ]
    bvs = {name: binaryninja.load(str(elf_fixtures / name)) for name in elf_names}
    yield bvs
    for bv in bvs.values():
        bv.file.close()


# ---- ARM (LE, ARM mode) ----


class TestARMElf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["arm_le.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_ARM
        assert ks._mode == keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_ARM
        assert cs.mode == capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_ARM
        assert uc._mode == unicorn.UC_MODE_ARM | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- ARM Thumb (LE) ----


class TestARMThumbElf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["arm_thumb_le.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_ARM
        assert ks._mode == keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_ARM
        assert cs.mode == capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_ARM
        assert uc._mode == unicorn.UC_MODE_THUMB | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- AArch64 (LE) ----


class TestAArch64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["aarch64_le.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_ARM64
        assert ks._mode == keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_ARM64
        assert cs.mode == capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_ARM64
        assert uc._mode == unicorn.UC_MODE_LITTLE_ENDIAN


# ---- MIPS32 (BE) ----


class TestMIPS32BEElf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["mips32_be.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS32 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN


# ---- MIPS32 (LE) — not supported by Binary Ninja ----


class TestMIPS32LEElf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["mips32_le.elf"]

    def test_ks_not_supported(self):
        with pytest.raises(ValueError, match="Unsupported Binary Ninja architecture"):
            Ks(self.bv)

    def test_cs_not_supported(self):
        with pytest.raises(ValueError, match="Unsupported Binary Ninja architecture"):
            Cs(self.bv)

    def test_uc_not_supported(self):
        with pytest.raises(ValueError, match="Unsupported Binary Ninja architecture"):
            Uc(self.bv)


# ---- MIPS64 (BE) ----


class TestMIPS64BEElf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["mips64_be.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- PPC32 (BE) ----


class TestPPC32Elf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["ppc32_be.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_PPC
        assert ks._mode == keystone.KS_MODE_PPC32 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_PPC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_PPC
        assert uc._mode == unicorn.UC_MODE_PPC32 | unicorn.UC_MODE_BIG_ENDIAN


# ---- PPC64 (BE) ----


class TestPPC64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["ppc64_be.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_PPC
        assert ks._mode == keystone.KS_MODE_PPC64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_PPC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_PPC
        assert uc._mode == unicorn.UC_MODE_PPC64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- RISC-V 64 (LE) — no Ks support ----


class TestRISCV64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["riscv64_le.elf"]

    def test_ks_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Ks(self.bv)

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_RISCV
        assert cs.mode == capstone.CS_MODE_RISCV64 | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_RISCV
        assert uc._mode == unicorn.UC_MODE_RISCV64 | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- X86 32-bit (LE) ----


class TestX86_32Elf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["x86_32_le.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_X86
        assert ks._mode == keystone.KS_MODE_32

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_X86
        assert cs.mode == capstone.CS_MODE_32

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_X86
        assert uc._mode == unicorn.UC_MODE_32


# ---- X86-64 (LE) ----


class TestX86_64Elf:
    @pytest.fixture(autouse=True)
    def setup(self, binja_bvs):
        self.bv = binja_bvs["x86_64_le.elf"]

    def test_ks(self):
        ks = Ks(self.bv)
        assert ks._arch == keystone.KS_ARCH_X86
        assert ks._mode == keystone.KS_MODE_64

    def test_cs(self):
        cs = Cs(self.bv)
        assert cs.arch == capstone.CS_ARCH_X86
        assert cs.mode == capstone.CS_MODE_64

    def test_uc(self):
        uc = Uc(self.bv)
        assert uc._arch == unicorn.UC_ARCH_X86
        assert uc._mode == unicorn.UC_MODE_64
