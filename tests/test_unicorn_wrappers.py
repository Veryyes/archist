"""Tests for Unicorn wrapper (.Uc()) creation on all architecture classes."""

import pytest

from archist import (
    ARM,
    ARM64,
    M68K,
    MIPS,
    PPC,
    RISCV,
    SPARC,
    TRICORE,
    X86,
)


# ---- ARM ----


class TestARMUc:
    def test_mode_object(self):
        uc = ARM.Uc(mode=ARM.Modes.thumb)
        assert uc is not None

    def test_mode_string(self):
        uc = ARM.Uc(mode="thumb")
        assert uc is not None

    def test_mode_arm(self):
        uc = ARM.Uc(mode="arm")
        assert uc is not None

    def test_mode_mclass(self):
        uc = ARM.Uc(mode="mclass")
        assert uc is not None

    def test_v8_not_in_uc_api(self):
        # v8 is not a valid modifier for Unicorn ARM — not in ARM.Uc() signature
        with pytest.raises(TypeError):
            ARM.Uc(mode="arm", v8=True)

    def test_mode_arm1176(self):
        uc = ARM.Uc(mode="arm1176")
        assert uc is not None

    def test_mode_armbe8(self):
        uc = ARM.Uc(mode="armbe8")
        assert uc is not None

    def test_mode_arm946(self):
        uc = ARM.Uc(mode="arm946")
        assert uc is not None

    def test_mode_arm926(self):
        uc = ARM.Uc(mode="arm926")
        assert uc is not None


# ---- ARM64 ----


class TestARM64Uc:
    def test(self):
        uc = ARM64.Uc()
        assert uc is not None


# ---- M68K ----


class TestM68KUc:
    def test_mode_object(self):
        uc = M68K.Uc(endian="big")
        assert uc is not None


# ---- MIPS ----


class TestMIPSUc:
    def test_mode_mips32(self):
        uc = MIPS.Uc(mode="mips32")
        assert uc is not None

    def test_mode_mips64(self):
        uc = MIPS.Uc(mode="mips64")
        assert uc is not None

    def test_mode_object(self):
        uc = MIPS.Uc(mode=MIPS.Modes.mips32)
        assert uc is not None

    def test_micro_not_in_uc_api(self):
        # micro is not a valid modifier for Unicorn MIPS — not in MIPS.Uc() signature
        with pytest.raises(TypeError):
            MIPS.Uc(mode="mips32", micro=True)

    def test_mips2_not_in_uc_api(self):
        # mips2 (UC_MODE_MIPS2) does not exist in Unicorn — not in MIPS.Uc() signature
        with pytest.raises(TypeError):
            MIPS.Uc(mode="mips32", mips2=True)

    def test_mips3_not_in_uc_api(self):
        # mips3 is not a valid modifier for Unicorn MIPS — not in MIPS.Uc() signature
        with pytest.raises(TypeError):
            MIPS.Uc(mode="mips32", mips3=True)

    def test_mips32r6_not_in_uc_api(self):
        # mips32r6 is not a valid modifier for Unicorn MIPS — not in MIPS.Uc() signature
        with pytest.raises(TypeError):
            MIPS.Uc(mode="mips32", mips32r6=True)


# ---- PPC ----


class TestPPCUc:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "ppc32",
            "ppc64",
        ],
    )
    def test_mode_string(self, mode_name):
        uc = PPC.Uc(mode=mode_name, endian="big")
        assert uc is not None

    def test_mode_object(self):
        uc = PPC.Uc(mode=PPC.Modes.ppc32, endian="big")
        assert uc is not None

    def test_mode_64_string(self):
        uc = PPC.Uc(mode="64", endian="big")
        assert uc is not None

    def test_mode_64_int(self):
        uc = PPC.Uc(mode=64, endian="big")
        assert uc is not None


# ---- RISCV ----


class TestRISCVUc:
    @pytest.mark.parametrize(
        "mode_name",
        [
            "riscv32",
            "riscv64",
        ],
    )
    def test_mode_string(self, mode_name):
        uc = RISCV.Uc(mode=mode_name)
        assert uc is not None

    def test_mode_object(self):
        uc = RISCV.Uc(mode=RISCV.Modes.riscv32)
        assert uc is not None


# ---- SPARC ----


class TestSPARCUc:
    def test_mode_sparc32(self):
        uc = SPARC.Uc(mode="sparc32", endian="big")
        assert uc is not None

    def test_mode_sparc64(self):
        uc = SPARC.Uc(mode="sparc64", endian="big")
        assert uc is not None

    def test_mode_object(self):
        uc = SPARC.Uc(mode=SPARC.Modes.sparc32, endian="big")
        assert uc is not None

    def test_v9_not_in_uc_api(self):
        # v9 is not a valid modifier for Unicorn SPARC — not in SPARC.Uc() signature
        with pytest.raises(TypeError):
            SPARC.Uc(mode="sparc32", endian="big", v9=True)


# ---- TRICORE ----


class TestTRICOREUc:
    def test_mode_object(self):
        uc = TRICORE.Uc()
        assert uc is not None


# ---- X86 ----


class TestX86Uc:
    def test_mode_32_int(self):
        uc = X86.Uc(mode=32)
        assert uc is not None

    def test_mode_32_string(self):
        uc = X86.Uc(mode="32")
        assert uc is not None

    def test_mode_16_int(self):
        uc = X86.Uc(mode=16)
        assert uc is not None

    def test_mode_16_string(self):
        uc = X86.Uc(mode="16")
        assert uc is not None

    def test_mode_object(self):
        uc = X86.Uc(mode=X86.Modes._32)
        assert uc is not None
