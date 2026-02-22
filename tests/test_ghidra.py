"""Tests for archist.extensions.ghidra using real ELF binaries loaded via pyghidra."""

import tempfile

import pytest
import keystone
import capstone
import unicorn


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

    tmpdir = tempfile.mkdtemp()
    project = pyghidra.open_project(tmpdir, "archist_test", create=True)

    for name in _LOADABLE_ELFS:
        elf_path = str((elf_fixtures / name).resolve())
        result = pyghidra.program_loader().project(project).source(elf_path).load()
        result.save(TaskMonitor.DUMMY)
        result.release(None)

    yield project
    project.close()


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


# ---- ARM (LE, ARM mode) ----


class TestARMElf:
    def test_ks(self, arm_le_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(arm_le_program), keystone.Ks)

    def test_cs(self, arm_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(arm_le_program), capstone.Cs)

    def test_uc(self, arm_le_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(arm_le_program), unicorn.Uc)


# ---- ARM Thumb (LE) ----


class TestARMThumbElf:
    def test_ks(self, arm_thumb_le_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(arm_thumb_le_program), keystone.Ks)

    def test_cs(self, arm_thumb_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(arm_thumb_le_program), capstone.Cs)

    def test_uc(self, arm_thumb_le_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(arm_thumb_le_program), unicorn.Uc)


# ---- AArch64 (LE) ----


class TestAArch64Elf:
    def test_ks(self, aarch64_le_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(aarch64_le_program), keystone.Ks)

    def test_cs(self, aarch64_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(aarch64_le_program), capstone.Cs)

    def test_uc(self, aarch64_le_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(aarch64_le_program), unicorn.Uc)


# ---- MIPS32 (BE) ----


class TestMIPS32BEElf:
    def test_ks(self, mips32_be_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(mips32_be_program), keystone.Ks)

    def test_cs(self, mips32_be_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(mips32_be_program), capstone.Cs)

    def test_uc(self, mips32_be_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(mips32_be_program), unicorn.Uc)


# ---- MIPS32 (LE) ----


class TestMIPS32LEElf:
    def test_ks(self, mips32_le_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(mips32_le_program), keystone.Ks)

    def test_cs(self, mips32_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(mips32_le_program), capstone.Cs)

    def test_uc(self, mips32_le_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(mips32_le_program), unicorn.Uc)


# ---- MIPS64 (BE) ----


class TestMIPS64BEElf:
    def test_ks(self, mips64_be_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(mips64_be_program), keystone.Ks)

    def test_cs(self, mips64_be_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(mips64_be_program), capstone.Cs)

    def test_uc(self, mips64_be_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(mips64_be_program), unicorn.Uc)


# ---- PPC32 (BE) ----


class TestPPC32Elf:
    def test_ks(self, ppc32_be_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(ppc32_be_program), keystone.Ks)

    def test_cs(self, ppc32_be_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(ppc32_be_program), capstone.Cs)

    def test_uc(self, ppc32_be_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(ppc32_be_program), unicorn.Uc)


# ---- PPC64 (BE) ----


class TestPPC64Elf:
    def test_ks(self, ppc64_be_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(ppc64_be_program), keystone.Ks)

    def test_cs(self, ppc64_be_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(ppc64_be_program), capstone.Cs)

    def test_uc(self, ppc64_be_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(ppc64_be_program), unicorn.Uc)


# ---- SPARC64 (BE) ----


class TestSPARC64Elf:
    def test_ks(self, sparc64_be_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(sparc64_be_program), keystone.Ks)

    def test_cs(self, sparc64_be_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(sparc64_be_program), capstone.Cs)

    def test_uc(self, sparc64_be_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(sparc64_be_program), unicorn.Uc)


# ---- RISC-V 64 (LE) — no Ks support ----


class TestRISCV64Elf:
    def test_ks_not_implemented(self, riscv64_le_program):
        from archist.extensions.ghidra import Ks

        with pytest.raises(NotImplementedError):
            Ks(riscv64_le_program)

    def test_cs(self, riscv64_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(riscv64_le_program), capstone.Cs)

    def test_uc(self, riscv64_le_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(riscv64_le_program), unicorn.Uc)


# ---- M68K (BE) — no Ks support ----


class TestM68KElf:
    def test_ks_not_implemented(self, m68k_be_program):
        from archist.extensions.ghidra import Ks

        with pytest.raises(NotImplementedError):
            Ks(m68k_be_program)

    def test_cs(self, m68k_be_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(m68k_be_program), capstone.Cs)

    def test_uc(self, m68k_be_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(m68k_be_program), unicorn.Uc)


# ---- SH4 (LE) — Cs only ----


class TestSH4Elf:
    def test_ks_not_implemented(self, sh4_le_program):
        from archist.extensions.ghidra import Ks

        with pytest.raises(NotImplementedError):
            Ks(sh4_le_program)

    def test_cs(self, sh4_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(sh4_le_program), capstone.Cs)

    def test_uc_not_implemented(self, sh4_le_program):
        from archist.extensions.ghidra import Uc

        with pytest.raises(NotImplementedError):
            Uc(sh4_le_program)


# ---- X86 32-bit (LE) ----


class TestX86_32Elf:
    def test_ks(self, x86_32_le_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(x86_32_le_program), keystone.Ks)

    def test_cs(self, x86_32_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(x86_32_le_program), capstone.Cs)

    def test_uc(self, x86_32_le_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(x86_32_le_program), unicorn.Uc)


# ---- X86-64 (LE) ----


class TestX86_64Elf:
    def test_ks(self, x86_64_le_program):
        from archist.extensions.ghidra import Ks

        assert isinstance(Ks(x86_64_le_program), keystone.Ks)

    def test_cs(self, x86_64_le_program):
        from archist.extensions.ghidra import Cs

        assert isinstance(Cs(x86_64_le_program), capstone.Cs)

    def test_uc(self, x86_64_le_program):
        from archist.extensions.ghidra import Uc

        assert isinstance(Uc(x86_64_le_program), unicorn.Uc)
