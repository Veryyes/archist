'''Different Modes Collated'''
import capstone
import keystone
import unicorn

import archist.core

###############################
# ARCHITECTURE MODES/VARIANTS #
###############################

MIPS3 = archist.core.Mode(
    name = "MIPS3",
    ks = keystone.KS_MODE_MIPS3,
    cs = capstone.CS_MODE_MIPS3,
    uc = unicorn.UC_MODE_MIPS3
)

V8 = archist.core.Mode(
    name = "V8",
    ks = keystone.KS_MODE_V8,
    cs = capstone.CS_MODE_V8,
    uc = unicorn.UC_MODE_V8
)

MOS65XX_65816 = archist.core.Mode(
    name = "MOS65XX_65816",
    ks = None,
    cs = capstone.CS_MODE_MOS65XX_65816,
    uc = None
)

M680X_6811 = archist.core.Mode(
    name = "M680X_6811",
    ks = None,
    cs = capstone.CS_MODE_M680X_6811,
    uc = None
)

TRICORE_120 = archist.core.Mode(
    name = "TRICORE_120",
    ks = None,
    cs = capstone.CS_MODE_TRICORE_120,
    uc = None
)

MOS65XX_65C02 = archist.core.Mode(
    name = "MOS65XX_65C02",
    ks = None,
    cs = capstone.CS_MODE_MOS65XX_65C02,
    uc = None
)

PS = archist.core.Mode(
    name = "PS",
    ks = None,
    cs = capstone.CS_MODE_PS,
    uc = None
)

SH4 = archist.core.Mode(
    name = "SH4",
    ks = None,
    cs = capstone.CS_MODE_SH4,
    uc = None
)

MOS65XX_65816_LONG_M = archist.core.Mode(
    name = "MOS65XX_65816_LONG_M",
    ks = None,
    cs = capstone.CS_MODE_MOS65XX_65816_LONG_M,
    uc = None
)

ARM = archist.core.Mode(
    name = "ARM",
    ks = keystone.KS_MODE_ARM,
    cs = capstone.CS_MODE_ARM,
    uc = unicorn.UC_MODE_ARM
)

M680X_HCS08 = archist.core.Mode(
    name = "M680X_HCS08",
    ks = None,
    cs = capstone.CS_MODE_M680X_HCS08,
    uc = None
)

MIPS32R6 = archist.core.Mode(
    name = "MIPS32R6",
    ks = keystone.KS_MODE_MIPS32R6,
    cs = capstone.CS_MODE_MIPS32R6,
    uc = unicorn.UC_MODE_MIPS32R6
)

M680X_6808 = archist.core.Mode(
    name = "M680X_6808",
    ks = None,
    cs = capstone.CS_MODE_M680X_6808,
    uc = None
)

RISCVC = archist.core.Mode(
    name = "RISCVC",
    ks = None,
    cs = capstone.CS_MODE_RISCVC,
    uc = None
)

SHFPU = archist.core.Mode(
    name = "SHFPU",
    ks = None,
    cs = capstone.CS_MODE_SHFPU,
    uc = None
)

V9 = archist.core.Mode(
    name = "V9",
    ks = keystone.KS_MODE_V9,
    cs = capstone.CS_MODE_V9,
    uc = unicorn.UC_MODE_V9
)

_32 = archist.core.Mode(
    name = "_32",
    ks = keystone.KS_MODE_32,
    cs = capstone.CS_MODE_32,
    uc = unicorn.UC_MODE_32
)

MIPS2 = archist.core.Mode(
    name = "MIPS2",
    ks = None,
    cs = capstone.CS_MODE_MIPS2,
    uc = None
)

BOOKE = archist.core.Mode(
    name = "BOOKE",
    ks = None,
    cs = capstone.CS_MODE_BOOKE,
    uc = None
)

THUMB = archist.core.Mode(
    name = "THUMB",
    ks = keystone.KS_MODE_THUMB,
    cs = capstone.CS_MODE_THUMB,
    uc = unicorn.UC_MODE_THUMB
)

PPC64 = archist.core.Mode(
    name = "PPC64",
    ks = keystone.KS_MODE_PPC64,
    cs = None,
    uc = unicorn.UC_MODE_PPC64
)

MIPS64 = archist.core.Mode(
    name = "MIPS64",
    ks = keystone.KS_MODE_MIPS64,
    cs = capstone.CS_MODE_MIPS64,
    uc = unicorn.UC_MODE_MIPS64
)

M680X_6301 = archist.core.Mode(
    name = "M680X_6301",
    ks = None,
    cs = capstone.CS_MODE_M680X_6301,
    uc = None
)

TRICORE_160 = archist.core.Mode(
    name = "TRICORE_160",
    ks = None,
    cs = capstone.CS_MODE_TRICORE_160,
    uc = None
)

BPF_CLASSIC = archist.core.Mode(
    name = "BPF_CLASSIC",
    ks = None,
    cs = capstone.CS_MODE_BPF_CLASSIC,
    uc = None
)

RISCV32 = archist.core.Mode(
    name = "RISCV32",
    ks = None,
    cs = capstone.CS_MODE_RISCV32,
    uc = unicorn.UC_MODE_RISCV32
)

RISCV64 = archist.core.Mode(
    name = "RISCV64",
    ks = None,
    cs = capstone.CS_MODE_RISCV64,
    uc = unicorn.UC_MODE_RISCV64
)

PPC32 = archist.core.Mode(
    name = "PPC32",
    ks = keystone.KS_MODE_PPC32,
    cs = None,
    uc = unicorn.UC_MODE_PPC32
)

TRICORE_110 = archist.core.Mode(
    name = "TRICORE_110",
    ks = None,
    cs = capstone.CS_MODE_TRICORE_110,
    uc = None
)

SPARC32 = archist.core.Mode(
    name = "SPARC32",
    ks = keystone.KS_MODE_SPARC32,
    cs = None,
    uc = unicorn.UC_MODE_SPARC32
)

_16 = archist.core.Mode(
    name = "_16",
    ks = keystone.KS_MODE_16,
    cs = capstone.CS_MODE_16,
    uc = unicorn.UC_MODE_16
)

TRICORE_130 = archist.core.Mode(
    name = "TRICORE_130",
    ks = None,
    cs = capstone.CS_MODE_TRICORE_130,
    uc = None
)

M68K_000 = archist.core.Mode(
    name = "M68K_000",
    ks = None,
    cs = capstone.CS_MODE_M68K_000,
    uc = None
)

QPX = archist.core.Mode(
    name = "QPX",
    ks = keystone.KS_MODE_QPX,
    cs = capstone.CS_MODE_QPX,
    uc = unicorn.UC_MODE_QPX
)

M68K_030 = archist.core.Mode(
    name = "M68K_030",
    ks = None,
    cs = capstone.CS_MODE_M68K_030,
    uc = None
)

ARM1176 = archist.core.Mode(
    name = "ARM1176",
    ks = None,
    cs = None,
    uc = unicorn.UC_MODE_ARM1176
)

MICRO = archist.core.Mode(
    name = "MICRO",
    ks = keystone.KS_MODE_MICRO,
    cs = capstone.CS_MODE_MICRO,
    uc = unicorn.UC_MODE_MICRO
)

SH2A = archist.core.Mode(
    name = "SH2A",
    ks = None,
    cs = capstone.CS_MODE_SH2A,
    uc = None
)

SH4A = archist.core.Mode(
    name = "SH4A",
    ks = None,
    cs = capstone.CS_MODE_SH4A,
    uc = None
)

SH3 = archist.core.Mode(
    name = "SH3",
    ks = None,
    cs = capstone.CS_MODE_SH3,
    uc = None
)

BPF_EXTENDED = archist.core.Mode(
    name = "BPF_EXTENDED",
    ks = None,
    cs = capstone.CS_MODE_BPF_EXTENDED,
    uc = None
)

MIPS32 = archist.core.Mode(
    name = "MIPS32",
    ks = keystone.KS_MODE_MIPS32,
    cs = capstone.CS_MODE_MIPS32,
    uc = unicorn.UC_MODE_MIPS32
)

M68K_060 = archist.core.Mode(
    name = "M68K_060",
    ks = None,
    cs = capstone.CS_MODE_M68K_060,
    uc = None
)

SH2 = archist.core.Mode(
    name = "SH2",
    ks = None,
    cs = capstone.CS_MODE_SH2,
    uc = None
)

TRICORE_161 = archist.core.Mode(
    name = "TRICORE_161",
    ks = None,
    cs = capstone.CS_MODE_TRICORE_161,
    uc = None
)

_64 = archist.core.Mode(
    name = "_64",
    ks = keystone.KS_MODE_64,
    cs = capstone.CS_MODE_64,
    uc = unicorn.UC_MODE_64
)

M68K_040 = archist.core.Mode(
    name = "M68K_040",
    ks = None,
    cs = capstone.CS_MODE_M68K_040,
    uc = None
)

MOS65XX_6502 = archist.core.Mode(
    name = "MOS65XX_6502",
    ks = None,
    cs = capstone.CS_MODE_MOS65XX_6502,
    uc = None
)

M680X_6800 = archist.core.Mode(
    name = "M680X_6800",
    ks = None,
    cs = capstone.CS_MODE_M680X_6800,
    uc = None
)

M680X_6809 = archist.core.Mode(
    name = "M680X_6809",
    ks = None,
    cs = capstone.CS_MODE_M680X_6809,
    uc = None
)

SPARC64 = archist.core.Mode(
    name = "SPARC64",
    ks = keystone.KS_MODE_SPARC64,
    cs = None,
    uc = unicorn.UC_MODE_SPARC64
)

M680X_CPU12 = archist.core.Mode(
    name = "M680X_CPU12",
    ks = None,
    cs = capstone.CS_MODE_M680X_CPU12,
    uc = None
)

M68K_010 = archist.core.Mode(
    name = "M68K_010",
    ks = None,
    cs = capstone.CS_MODE_M68K_010,
    uc = None
)

SHDSP = archist.core.Mode(
    name = "SHDSP",
    ks = None,
    cs = capstone.CS_MODE_SHDSP,
    uc = None
)

M68K_020 = archist.core.Mode(
    name = "M68K_020",
    ks = None,
    cs = capstone.CS_MODE_M68K_020,
    uc = None
)

ARM946 = archist.core.Mode(
    name = "ARM946",
    ks = None,
    cs = None,
    uc = unicorn.UC_MODE_ARM946
)

TRICORE_131 = archist.core.Mode(
    name = "TRICORE_131",
    ks = None,
    cs = capstone.CS_MODE_TRICORE_131,
    uc = None
)

M680X_6805 = archist.core.Mode(
    name = "M680X_6805",
    ks = None,
    cs = capstone.CS_MODE_M680X_6805,
    uc = None
)

M680X_6309 = archist.core.Mode(
    name = "M680X_6309",
    ks = None,
    cs = capstone.CS_MODE_M680X_6309,
    uc = None
)

SPE = archist.core.Mode(
    name = "SPE",
    ks = None,
    cs = capstone.CS_MODE_SPE,
    uc = None
)

MCLASS = archist.core.Mode(
    name = "MCLASS",
    ks = None,
    cs = capstone.CS_MODE_MCLASS,
    uc = unicorn.UC_MODE_MCLASS
)

TRICORE_162 = archist.core.Mode(
    name = "TRICORE_162",
    ks = None,
    cs = capstone.CS_MODE_TRICORE_162,
    uc = None
)

MOS65XX_65816_LONG_X = archist.core.Mode(
    name = "MOS65XX_65816_LONG_X",
    ks = None,
    cs = capstone.CS_MODE_MOS65XX_65816_LONG_X,
    uc = None
)

ARMBE8 = archist.core.Mode(
    name = "ARMBE8",
    ks = None,
    cs = None,
    uc = unicorn.UC_MODE_ARMBE8
)

MOS65XX_W65C02 = archist.core.Mode(
    name = "MOS65XX_W65C02",
    ks = None,
    cs = capstone.CS_MODE_MOS65XX_W65C02,
    uc = None
)

M680X_6801 = archist.core.Mode(
    name = "M680X_6801",
    ks = None,
    cs = capstone.CS_MODE_M680X_6801,
    uc = None
)

ARM926 = archist.core.Mode(
    name = "ARM926",
    ks = None,
    cs = None,
    uc = unicorn.UC_MODE_ARM926
)

MOS65XX_65816_LONG_MX = archist.core.Mode(
    name = "MOS65XX_65816_LONG_MX",
    ks = None,
    cs = capstone.CS_MODE_MOS65XX_65816_LONG_MX,
    uc = None
)

ALL_MODES = [MIPS3, V8, MOS65XX_65816, M680X_6811, TRICORE_120, MOS65XX_65C02, PS, SH4, MOS65XX_65816_LONG_M, ARM, M680X_HCS08, MIPS32R6, M680X_6808, RISCVC, SHFPU, V9, _32, MIPS2, BOOKE, THUMB, PPC64, MIPS64, M680X_6301, TRICORE_160, BPF_CLASSIC, RISCV32, RISCV64, PPC32, TRICORE_110, SPARC32, _16, TRICORE_130, M68K_000, QPX, M68K_030, ARM1176, MICRO, SH2A, SH4A, SH3, BPF_EXTENDED, MIPS32, M68K_060, SH2, TRICORE_161, _64, M68K_040, MOS65XX_6502, M680X_6800, M680X_6809, SPARC64, M680X_CPU12, M68K_010, SHDSP, M68K_020, ARM946, TRICORE_131, M680X_6805, M680X_6309, SPE, MCLASS, TRICORE_162, MOS65XX_65816_LONG_X, ARMBE8, MOS65XX_W65C02, M680X_6801, ARM926, MOS65XX_65816_LONG_MX]