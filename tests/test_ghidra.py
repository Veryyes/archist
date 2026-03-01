"""Tests for archist.extensions.ghidra using real ELF binaries loaded via pyghidra."""

import tempfile
import shutil

import pytest
import keystone
import capstone
import unicorn

from archist.extensions.ghidra import Ks, Cs, Uc

pyghidra = pytest.importorskip("pyghidra")


# ELFs that Ghidra can load (s390x fails with "No load spec found")
_LOADABLE_ELFS = [
    "arm_le.elf",
    "arm_thumb_le.elf",
    "aarch64_le.elf",
    "mips32_be.elf",
    "mips32_le.elf",
    "mips64_be.elf",
    "ppc32_be.elf",
    "ppc64_be.elf",
    "sparc64_be.elf",
    "riscv64_le.elf",
    "m68k_be.elf",
    "sh4_le.elf",
    "x86_32_le.elf",
    "x86_64_le.elf",
]


@pytest.fixture(scope="session")
def ghidra_project(elf_fixtures):
    """Start pyghidra, create a project, and import all loadable ELF fixtures."""
    pyghidra.start()
    from ghidra.util.task import TaskMonitor

    try:
        tmpdir = tempfile.mkdtemp()
        project = pyghidra.open_project(tmpdir, "archist_test", create=True)

        for name in _LOADABLE_ELFS:
            elf_path = str((elf_fixtures / name).resolve())
            result = pyghidra.program_loader().project(project).source(elf_path).load()
            result.save(TaskMonitor.DUMMY)
            result.release(None)

        yield project
    finally:
        project.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


def _program(ghidra_project, name):
    return pyghidra.program_context(ghidra_project, f"/{name}")


# ---- per-binary fixtures ----


@pytest.fixture()
def arm_le_program(ghidra_project):
    with _program(ghidra_project, "arm_le.elf") as prog:
        yield prog


@pytest.fixture()
def arm_thumb_le_program(ghidra_project):
    with _program(ghidra_project, "arm_thumb_le.elf") as prog:
        yield prog


@pytest.fixture()
def aarch64_le_program(ghidra_project):
    with _program(ghidra_project, "aarch64_le.elf") as prog:
        yield prog


@pytest.fixture()
def mips32_be_program(ghidra_project):
    with _program(ghidra_project, "mips32_be.elf") as prog:
        yield prog


@pytest.fixture()
def mips32_le_program(ghidra_project):
    with _program(ghidra_project, "mips32_le.elf") as prog:
        yield prog


@pytest.fixture()
def mips64_be_program(ghidra_project):
    with _program(ghidra_project, "mips64_be.elf") as prog:
        yield prog


@pytest.fixture()
def ppc32_be_program(ghidra_project):
    with _program(ghidra_project, "ppc32_be.elf") as prog:
        yield prog


@pytest.fixture()
def ppc64_be_program(ghidra_project):
    with _program(ghidra_project, "ppc64_be.elf") as prog:
        yield prog


@pytest.fixture()
def sparc64_be_program(ghidra_project):
    with _program(ghidra_project, "sparc64_be.elf") as prog:
        yield prog


@pytest.fixture()
def riscv64_le_program(ghidra_project):
    with _program(ghidra_project, "riscv64_le.elf") as prog:
        yield prog


@pytest.fixture()
def m68k_be_program(ghidra_project):
    with _program(ghidra_project, "m68k_be.elf") as prog:
        yield prog


@pytest.fixture()
def sh4_le_program(ghidra_project):
    with _program(ghidra_project, "sh4_le.elf") as prog:
        yield prog


@pytest.fixture()
def x86_32_le_program(ghidra_project):
    with _program(ghidra_project, "x86_32_le.elf") as prog:
        yield prog


@pytest.fixture()
def x86_64_le_program(ghidra_project):
    with _program(ghidra_project, "x86_64_le.elf") as prog:
        yield prog


# s390x is skipped — Ghidra cannot load it ("No load spec found")

# NOTE: Ghidra identifies both arm_le.elf and arm_thumb_le.elf as ARM:LE:32:v8
# (ARM mode), so both ARM test classes expect ARM mode rather than Thumb.


# ---- ARM (LE, ARM mode) ----


class TestARMElf:
    def test_ks(self, arm_le_program):
        ks = Ks(arm_le_program)
        assert ks._arch == keystone.KS_ARCH_ARM
        assert ks._mode == keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self, arm_le_program):
        cs = Cs(arm_le_program)
        assert cs.arch == capstone.CS_ARCH_ARM
        assert cs.mode == capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self, arm_le_program):
        uc = Uc(arm_le_program)
        assert uc._arch == unicorn.UC_ARCH_ARM
        assert uc._mode == unicorn.UC_MODE_ARM | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- ARM Thumb (LE) — Ghidra detects as ARM mode ----


class TestARMThumbElf:
    def test_ks(self, arm_thumb_le_program):
        ks = Ks(arm_thumb_le_program)
        assert ks._arch == keystone.KS_ARCH_ARM
        assert ks._mode == keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self, arm_thumb_le_program):
        cs = Cs(arm_thumb_le_program)
        assert cs.arch == capstone.CS_ARCH_ARM
        assert cs.mode == capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self, arm_thumb_le_program):
        uc = Uc(arm_thumb_le_program)
        assert uc._arch == unicorn.UC_ARCH_ARM
        assert uc._mode == unicorn.UC_MODE_ARM | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- AArch64 (LE) ----


class TestAArch64Elf:
    def test_ks(self, aarch64_le_program):
        ks = Ks(aarch64_le_program)
        assert ks._arch == keystone.KS_ARCH_ARM64
        assert ks._mode == keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self, aarch64_le_program):
        cs = Cs(aarch64_le_program)
        assert cs.arch == capstone.CS_ARCH_ARM64
        assert cs.mode == capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self, aarch64_le_program):
        uc = Uc(aarch64_le_program)
        assert uc._arch == unicorn.UC_ARCH_ARM64
        assert uc._mode == unicorn.UC_MODE_LITTLE_ENDIAN


# ---- MIPS32 (BE) ----


class TestMIPS32BEElf:
    def test_ks(self, mips32_be_program):
        ks = Ks(mips32_be_program)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS32 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self, mips32_be_program):
        cs = Cs(mips32_be_program)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self, mips32_be_program):
        uc = Uc(mips32_be_program)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN


# ---- MIPS32 (LE) ----


class TestMIPS32LEElf:
    def test_ks(self, mips32_le_program):
        ks = Ks(mips32_le_program)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS32 | keystone.KS_MODE_LITTLE_ENDIAN

    def test_cs(self, mips32_le_program):
        cs = Cs(mips32_le_program)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self, mips32_le_program):
        uc = Uc(mips32_le_program)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- MIPS64 (BE) ----


class TestMIPS64BEElf:
    def test_ks(self, mips64_be_program):
        ks = Ks(mips64_be_program)
        assert ks._arch == keystone.KS_ARCH_MIPS
        assert ks._mode == keystone.KS_MODE_MIPS64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self, mips64_be_program):
        cs = Cs(mips64_be_program)
        assert cs.arch == capstone.CS_ARCH_MIPS
        assert cs.mode == capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self, mips64_be_program):
        uc = Uc(mips64_be_program)
        assert uc._arch == unicorn.UC_ARCH_MIPS
        assert uc._mode == unicorn.UC_MODE_MIPS64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- PPC32 (BE) ----


class TestPPC32Elf:
    def test_ks(self, ppc32_be_program):
        ks = Ks(ppc32_be_program)
        assert ks._arch == keystone.KS_ARCH_PPC
        assert ks._mode == keystone.KS_MODE_PPC32 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self, ppc32_be_program):
        cs = Cs(ppc32_be_program)
        assert cs.arch == capstone.CS_ARCH_PPC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self, ppc32_be_program):
        uc = Uc(ppc32_be_program)
        assert uc._arch == unicorn.UC_ARCH_PPC
        assert uc._mode == unicorn.UC_MODE_PPC32 | unicorn.UC_MODE_BIG_ENDIAN


# ---- PPC64 (BE) ----


class TestPPC64Elf:
    def test_ks(self, ppc64_be_program):
        ks = Ks(ppc64_be_program)
        assert ks._arch == keystone.KS_ARCH_PPC
        assert ks._mode == keystone.KS_MODE_PPC64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self, ppc64_be_program):
        cs = Cs(ppc64_be_program)
        assert cs.arch == capstone.CS_ARCH_PPC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self, ppc64_be_program):
        uc = Uc(ppc64_be_program)
        assert uc._arch == unicorn.UC_ARCH_PPC
        assert uc._mode == unicorn.UC_MODE_PPC64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- SPARC64 (BE) ----


class TestSPARC64Elf:
    def test_ks(self, sparc64_be_program):
        ks = Ks(sparc64_be_program)
        assert ks._arch == keystone.KS_ARCH_SPARC
        assert ks._mode == keystone.KS_MODE_SPARC64 | keystone.KS_MODE_BIG_ENDIAN

    def test_cs(self, sparc64_be_program):
        cs = Cs(sparc64_be_program)
        assert cs.arch == capstone.CS_ARCH_SPARC
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self, sparc64_be_program):
        uc = Uc(sparc64_be_program)
        assert uc._arch == unicorn.UC_ARCH_SPARC
        assert uc._mode == unicorn.UC_MODE_SPARC64 | unicorn.UC_MODE_BIG_ENDIAN


# ---- RISC-V 64 (LE) — no Ks support ----


class TestRISCV64Elf:
    def test_ks_not_implemented(self, riscv64_le_program):
        with pytest.raises(NotImplementedError):
            Ks(riscv64_le_program)

    def test_cs(self, riscv64_le_program):
        cs = Cs(riscv64_le_program)
        assert cs.arch == capstone.CS_ARCH_RISCV
        assert cs.mode == capstone.CS_MODE_RISCV64 | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc(self, riscv64_le_program):
        uc = Uc(riscv64_le_program)
        assert uc._arch == unicorn.UC_ARCH_RISCV
        assert uc._mode == unicorn.UC_MODE_RISCV64 | unicorn.UC_MODE_LITTLE_ENDIAN


# ---- M68K (BE) — no Ks support ----


class TestM68KElf:
    def test_ks_not_implemented(self, m68k_be_program):
        with pytest.raises(NotImplementedError):
            Ks(m68k_be_program)

    def test_cs(self, m68k_be_program):
        cs = Cs(m68k_be_program)
        assert cs.arch == capstone.CS_ARCH_M68K
        assert cs.mode == capstone.CS_MODE_BIG_ENDIAN

    def test_uc(self, m68k_be_program):
        uc = Uc(m68k_be_program)
        assert uc._arch == unicorn.UC_ARCH_M68K
        assert uc._mode == unicorn.UC_MODE_BIG_ENDIAN


# ---- SH4 (LE) — Cs only ----


class TestSH4Elf:
    def test_ks_not_implemented(self, sh4_le_program):
        with pytest.raises(NotImplementedError):
            Ks(sh4_le_program)

    def test_cs(self, sh4_le_program):
        cs = Cs(sh4_le_program)
        assert cs.arch == capstone.CS_ARCH_SH
        assert cs.mode == capstone.CS_MODE_SH4 | capstone.CS_MODE_LITTLE_ENDIAN

    def test_uc_not_implemented(self, sh4_le_program):
        with pytest.raises(NotImplementedError):
            Uc(sh4_le_program)


# ---- X86 32-bit (LE) ----


class TestX86_32Elf:
    def test_ks(self, x86_32_le_program):
        ks = Ks(x86_32_le_program)
        assert ks._arch == keystone.KS_ARCH_X86
        assert ks._mode == keystone.KS_MODE_32

    def test_cs(self, x86_32_le_program):
        cs = Cs(x86_32_le_program)
        assert cs.arch == capstone.CS_ARCH_X86
        assert cs.mode == capstone.CS_MODE_32

    def test_uc(self, x86_32_le_program):
        uc = Uc(x86_32_le_program)
        assert uc._arch == unicorn.UC_ARCH_X86
        assert uc._mode == unicorn.UC_MODE_32


# ---- X86-64 (LE) ----


class TestX86_64Elf:
    def test_ks(self, x86_64_le_program):
        ks = Ks(x86_64_le_program)
        assert ks._arch == keystone.KS_ARCH_X86
        assert ks._mode == keystone.KS_MODE_64

    def test_cs(self, x86_64_le_program):
        cs = Cs(x86_64_le_program)
        assert cs.arch == capstone.CS_ARCH_X86
        assert cs.mode == capstone.CS_MODE_64

    def test_uc(self, x86_64_le_program):
        uc = Uc(x86_64_le_program)
        assert uc._arch == unicorn.UC_ARCH_X86
        assert uc._mode == unicorn.UC_MODE_64
