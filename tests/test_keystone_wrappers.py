"""Tests for Keystone wrapper (.Ks()) creation on all architecture classes."""

import pytest
import keystone

from archist import (
    ARM,
    ARM64,
    MIPS,
    PPC,
    SPARC,
    X86,
)


# ---- ARM ----


class TestARMKs:
    def test_mode_object(self):
        ks = ARM.Ks(mode=ARM.Modes.thumb)
        assert ks is not None

    def test_mode_string(self):
        ks = ARM.Ks(mode="thumb")
        assert ks is not None

    def test_mode_arm(self):
        ks = ARM.Ks(mode="arm")
        assert ks is not None

    def test_mode_v8(self):
        ks = ARM.Ks(mode="arm", v8=True)
        assert ks._mode & keystone.KS_MODE_V8


# ---- ARM64 ----


class TestARM64Ks:
    def test(self):
        ks = ARM64.Ks()
        assert ks is not None


# ---- MIPS ----


class TestMIPSKs:
    def test_mode_mips32(self):
        ks = MIPS.Ks(mode="mips32")
        assert ks is not None

    def test_mode_mips64(self):
        ks = MIPS.Ks(mode="mips64")
        assert ks is not None

    def test_mode_object(self):
        ks = MIPS.Ks(mode=MIPS.Modes.mips32)
        assert ks is not None

    def test_micro_not_in_ks_api(self):
        # micro is not a valid modifier for Keystone MIPS — not in MIPS.Ks() signature
        with pytest.raises(TypeError):
            MIPS.Ks(mode="mips32", micro=True)

    def test_mips3_not_in_ks_api(self):
        # mips3 is not a valid modifier for Keystone MIPS — not in MIPS.Ks() signature
        with pytest.raises(TypeError):
            MIPS.Ks(mode="mips32", mips3=True)

    def test_mips32r6_not_in_ks_api(self):
        # mips32r6 is not a valid modifier for Keystone MIPS — not in MIPS.Ks() signature
        with pytest.raises(TypeError):
            MIPS.Ks(mode="mips32", mips32r6=True)


# ---- PPC ----


class TestPPCKs:
    def test_mode_string(self):
        ks = PPC.Ks(mode="ppc64")
        assert ks is not None

    def test_mode_64_string(self):
        ks = PPC.Ks(mode="64")
        assert ks is not None

    def test_mode_64_int(self):
        ks = PPC.Ks(mode=64)
        assert ks is not None


# ---- SPARC ----


class TestSPARCKs:
    def test_mode_sparc32(self):
        ks = SPARC.Ks(mode="sparc32")
        assert ks is not None

    def test_mode_sparc64(self):
        ks = SPARC.Ks(mode="sparc64", endian="big")
        assert ks is not None

    def test_mode_object(self):
        ks = SPARC.Ks(mode=SPARC.Modes.sparc32)
        assert ks is not None

    def test_v9(self):
        ks = SPARC.Ks(mode="sparc32", v9=True)
        assert ks._mode & keystone.KS_MODE_V9


# ---- X86 ----


class TestX86Ks:
    def test_mode_32_int(self):
        ks = X86.Ks(mode=32)
        assert ks is not None

    def test_mode_32_string(self):
        ks = X86.Ks(mode="32")
        assert ks is not None

    def test_mode_16_int(self):
        ks = X86.Ks(mode=16)
        assert ks is not None

    def test_mode_16_string(self):
        ks = X86.Ks(mode="16")
        assert ks is not None

    def test_mode_object(self):
        ks = X86.Ks(mode=X86.Modes._32)
        assert ks is not None
