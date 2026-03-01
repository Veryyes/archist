"""Tests for Capstone wrapper (.Cs()) creation on all architecture classes."""

import capstone
import pytest

from archist import (
    ARM,
    ARM64,
    BPF,
    M680X,
    M68K,
    MIPS,
    MOS65XX,
    PPC,
    RISCV,
    SH,
    SPARC,
    TRICORE,
    X86,
)


# ---- ARM ----


class TestARMCs:
    def test_mode_object(self):
        cs = ARM.Cs(mode=ARM.Modes.thumb)
        assert cs is not None

    def test_mode_string(self):
        cs = ARM.Cs(mode="thumb")
        assert cs is not None

    def test_mode_arm(self):
        cs = ARM.Cs(mode="arm")
        assert cs is not None

    def test_mode_mclass(self):
        cs = ARM.Cs(mode="mclass")
        assert cs is not None

    def test_mode_v8(self):
        cs = ARM.Cs(mode="arm", v8=True)
        assert cs.mode & capstone.CS_MODE_V8


# ---- ARM64 ----


class TestARM64Cs:
    def test_mode_object(self):
        cs = ARM64.Cs()
        assert cs is not None


# ---- BPF ----


class TestBPFCs:
    def test_mode_bpf_classic(self):
        cs = BPF.Cs(mode="bpf_classic")
        assert cs is not None

    def test_mode_bpf_extended(self):
        cs = BPF.Cs(mode="bpf_extended")
        assert cs is not None

    def test_mode_object(self):
        cs = BPF.Cs(mode=BPF.Modes.bpf_classic)
        assert cs is not None


# ---- M680X ----


class TestM680XCs:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "m680x_6301",
            "m680x_6309",
            "m680x_6800",
            "m680x_6801",
            "m680x_6805",
            "m680x_6808",
            "m680x_6809",
            "m680x_6811",
            "m680x_cpu12",
            "m680x_hcs08",
        ],
    )
    def test_mode_string(self, mode_name):
        cs = M680X.Cs(mode=mode_name)
        assert cs is not None

    def test_mode_object(self):
        cs = M680X.Cs(mode=M680X.Modes.m680x_6301)
        assert cs is not None


# ---- M68K ----


class TestM68KCs:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "m68k_000",
            "m68k_010",
            "m68k_020",
            "m68k_030",
            "m68k_040",
            "m68k_060",
        ],
    )
    def test_mode_string(self, mode_name):
        cs = M68K.Cs(mode=mode_name)
        assert cs is not None

    def test_mode_object(self):
        cs = M68K.Cs(mode=M68K.Modes.m68k_000)
        assert cs is not None


# ---- MIPS ----


class TestMIPSCs:
    def test_mode_mips32(self):
        cs = MIPS.Cs(mode="mips32")
        assert cs is not None

    def test_mode_mips64(self):
        cs = MIPS.Cs(mode="mips64")
        assert cs is not None

    def test_mode_object(self):
        cs = MIPS.Cs(mode=MIPS.Modes.mips32)
        assert cs is not None

    def test_micro(self):
        cs = MIPS.Cs(mode="mips32", micro=True)
        assert cs.mode & capstone.CS_MODE_MICRO

    def test_mips2(self):
        cs = MIPS.Cs(mode="mips32", mips2=True)
        assert cs.mode & capstone.CS_MODE_MIPS2

    def test_mips3(self):
        cs = MIPS.Cs(mode="mips32", mips3=True)
        assert cs.mode & capstone.CS_MODE_MIPS3

    def test_mips32r6(self):
        cs = MIPS.Cs(mode="mips32", mips32r6=True)
        assert cs.mode & capstone.CS_MODE_MIPS32R6


# ---- MOS65XX ----


class TestMOS65XXCs:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "mos65xx_6502",
            "mos65xx_65816_long_m",
            "mos65xx_65816_long_mx",
            "mos65xx_65816_long_x",
            "mos65xx_65c02",
            "mos65xx_w65c02",
        ],
    )
    def test_mode_string(self, mode_name):
        cs = MOS65XX.Cs(mode=mode_name)
        assert cs is not None

    def test_mode_object(self):
        cs = MOS65XX.Cs(mode=MOS65XX.Modes.mos65xx_6502)
        assert cs is not None


# ---- PPC ----


class TestPPCCs:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "qpx",
            "ps",
        ],
    )
    def test_mode_string(self, mode_name):
        cs = PPC.Cs(mode=mode_name)
        assert cs is not None

    def test_mode_object(self):
        cs = PPC.Cs()
        assert cs is not None

    def test_mode_64_string(self):
        cs = PPC.Cs(mode="64")
        assert cs is not None

    def test_mode_64_int(self):
        cs = PPC.Cs(mode=64)
        assert cs is not None


# ---- RISCV ----


class TestRISCVCs:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "riscv32",
            "riscv64",
            "riscvc",
        ],
    )
    def test_mode_string(self, mode_name):
        cs = RISCV.Cs(mode=mode_name)
        assert cs is not None

    def test_mode_object(self):
        cs = RISCV.Cs(mode=RISCV.Modes.riscv32)
        assert cs is not None


# ---- SH ----


class TestSHCs:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "sh2",
            "sh2a",
            "sh3",
            "sh4",
            "sh4a",
            "shdsp",
            "shfpu",
        ],
    )
    def test_mode_string(self, mode_name):
        cs = SH.Cs(mode=mode_name)
        assert cs is not None

    def test_mode_object(self):
        cs = SH.Cs(mode=SH.Modes.sh2)
        assert cs is not None


# ---- SPARC ----


class TestSPARCCs:
    def test_mode_sparc32(self):
        cs = SPARC.Cs()
        assert cs is not None

    def test_v9(self):
        cs = SPARC.Cs(v9=True)
        assert cs.mode & capstone.CS_MODE_V9


# ---- TRICORE ----


class TestTRICORECs:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "tricore_110",
            "tricore_120",
            "tricore_130",
            "tricore_131",
            "tricore_160",
            "tricore_161",
            "tricore_162",
        ],
    )
    def test_mode_string(self, mode_name):
        cs = TRICORE.Cs(mode=mode_name)
        assert cs is not None

    def test_mode_object(self):
        cs = TRICORE.Cs(mode=TRICORE.Modes.tricore_110)
        assert cs is not None


# ---- X86 ----


class TestX86Cs:
    def test_mode_32_int(self):
        cs = X86.Cs(mode=32)
        assert cs is not None

    def test_mode_32_string(self):
        cs = X86.Cs(mode="32")
        assert cs is not None

    def test_mode_16_int(self):
        cs = X86.Cs(mode=16)
        assert cs is not None

    def test_mode_16_string(self):
        cs = X86.Cs(mode="16")
        assert cs is not None

    def test_mode_object(self):
        cs = X86.Cs(mode=X86.Modes._32)
        assert cs is not None
