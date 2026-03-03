"""Exhaustive validation of all arch+mode combinations for capstone, keystone, and unicorn.

Tests every combination we believe should work (and some known-broken ones)
against the actually installed library versions.
"""

import sys

import capstone
import keystone
import unicorn

# ============================================================================
# CAPSTONE (v5 uses CS_ARCH_ARM64 and CS_ARCH_SYSZ)
# ============================================================================

CAPSTONE_COMBOS = [
    # (arch_name, arch_const, mode_name, mode_const)
    #
    # --- ARM ---
    ("ARM", capstone.CS_ARCH_ARM, "ARM (LE)", 0),
    ("ARM", capstone.CS_ARCH_ARM, "THUMB", capstone.CS_MODE_THUMB),
    (
        "ARM",
        capstone.CS_ARCH_ARM,
        "THUMB|MCLASS",
        capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS,
    ),
    (
        "ARM",
        capstone.CS_ARCH_ARM,
        "THUMB|V8",
        capstone.CS_MODE_THUMB | capstone.CS_MODE_V8,
    ),
    (
        "ARM",
        capstone.CS_ARCH_ARM,
        "THUMB|MCLASS|V8",
        capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS | capstone.CS_MODE_V8,
    ),
    ("ARM", capstone.CS_ARCH_ARM, "ARM|V8", capstone.CS_MODE_V8),
    ("ARM", capstone.CS_ARCH_ARM, "ARM (BE)", capstone.CS_MODE_BIG_ENDIAN),
    (
        "ARM",
        capstone.CS_ARCH_ARM,
        "THUMB (BE)",
        capstone.CS_MODE_THUMB | capstone.CS_MODE_BIG_ENDIAN,
    ),
    (
        "ARM",
        capstone.CS_ARCH_ARM,
        "THUMB|V8 (BE)",
        capstone.CS_MODE_THUMB | capstone.CS_MODE_V8 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    # --- ARM64 ---
    ("ARM64", capstone.CS_ARCH_ARM64, "LE", 0),
    ("ARM64", capstone.CS_ARCH_ARM64, "BE", capstone.CS_MODE_BIG_ENDIAN),
    # --- MIPS ---
    ("MIPS", capstone.CS_ARCH_MIPS, "MIPS32", capstone.CS_MODE_MIPS32),
    ("MIPS", capstone.CS_ARCH_MIPS, "MIPS64", capstone.CS_MODE_MIPS64),
    (
        "MIPS",
        capstone.CS_ARCH_MIPS,
        "MIPS32 (BE)",
        capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    (
        "MIPS",
        capstone.CS_ARCH_MIPS,
        "MIPS64 (BE)",
        capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    (
        "MIPS",
        capstone.CS_ARCH_MIPS,
        "MIPS32|MICRO",
        capstone.CS_MODE_MIPS32 | capstone.CS_MODE_MICRO,
    ),
    (
        "MIPS",
        capstone.CS_ARCH_MIPS,
        "MIPS32|MIPS32R6",
        capstone.CS_MODE_MIPS32 | capstone.CS_MODE_MIPS32R6,
    ),
    (
        "MIPS",
        capstone.CS_ARCH_MIPS,
        "MIPS32|MIPS2",
        capstone.CS_MODE_MIPS32 | capstone.CS_MODE_MIPS2,
    ),
    (
        "MIPS",
        capstone.CS_ARCH_MIPS,
        "MIPS32|MIPS3",
        capstone.CS_MODE_MIPS32 | capstone.CS_MODE_MIPS3,
    ),
    (
        "MIPS",
        capstone.CS_ARCH_MIPS,
        "MIPS64|MICRO",
        capstone.CS_MODE_MIPS64 | capstone.CS_MODE_MICRO,
    ),
    # --- X86 ---
    ("X86", capstone.CS_ARCH_X86, "16", capstone.CS_MODE_16),
    ("X86", capstone.CS_ARCH_X86, "32", capstone.CS_MODE_32),
    ("X86", capstone.CS_ARCH_X86, "64", capstone.CS_MODE_64),
    # --- PPC ---
    ("PPC", capstone.CS_ARCH_PPC, "32", capstone.CS_MODE_32),
    ("PPC", capstone.CS_ARCH_PPC, "64", capstone.CS_MODE_64),
    (
        "PPC",
        capstone.CS_ARCH_PPC,
        "32 (BE)",
        capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    (
        "PPC",
        capstone.CS_ARCH_PPC,
        "64 (BE)",
        capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    ("PPC", capstone.CS_ARCH_PPC, "32|QPX", capstone.CS_MODE_32 | capstone.CS_MODE_QPX),
    ("PPC", capstone.CS_ARCH_PPC, "32|PS", capstone.CS_MODE_32 | capstone.CS_MODE_PS),
    ("PPC", capstone.CS_ARCH_PPC, "32|SPE", capstone.CS_MODE_32 | capstone.CS_MODE_SPE),
    (
        "PPC",
        capstone.CS_ARCH_PPC,
        "32|BOOKE",
        capstone.CS_MODE_32 | capstone.CS_MODE_BOOKE,
    ),
    ("PPC", capstone.CS_ARCH_PPC, "LE (no size)", 0),
    ("PPC", capstone.CS_ARCH_PPC, "BE (no size)", capstone.CS_MODE_BIG_ENDIAN),
    # --- SPARC ---
    ("SPARC", capstone.CS_ARCH_SPARC, "BE", capstone.CS_MODE_BIG_ENDIAN),
    (
        "SPARC",
        capstone.CS_ARCH_SPARC,
        "BE|V9",
        capstone.CS_MODE_BIG_ENDIAN | capstone.CS_MODE_V9,
    ),
    ("SPARC", capstone.CS_ARCH_SPARC, "LE", 0),
    # --- SYSZ ---
    ("SYSZ", capstone.CS_ARCH_SYSZ, "BE", capstone.CS_MODE_BIG_ENDIAN),
    ("SYSZ", capstone.CS_ARCH_SYSZ, "LE", 0),
    # --- XCORE ---
    ("XCORE", capstone.CS_ARCH_XCORE, "BE", capstone.CS_MODE_BIG_ENDIAN),
    ("XCORE", capstone.CS_ARCH_XCORE, "LE", 0),
    # --- M68K ---
    ("M68K", capstone.CS_ARCH_M68K, "000", capstone.CS_MODE_M68K_000),
    ("M68K", capstone.CS_ARCH_M68K, "010", capstone.CS_MODE_M68K_010),
    ("M68K", capstone.CS_ARCH_M68K, "020", capstone.CS_MODE_M68K_020),
    ("M68K", capstone.CS_ARCH_M68K, "030", capstone.CS_MODE_M68K_030),
    ("M68K", capstone.CS_ARCH_M68K, "040", capstone.CS_MODE_M68K_040),
    ("M68K", capstone.CS_ARCH_M68K, "060", capstone.CS_MODE_M68K_060),
    (
        "M68K",
        capstone.CS_ARCH_M68K,
        "000 (BE)",
        capstone.CS_MODE_M68K_000 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    # --- TMS320C64X ---
    ("TMS320C64X", capstone.CS_ARCH_TMS320C64X, "LE", 0),
    ("TMS320C64X", capstone.CS_ARCH_TMS320C64X, "BE", capstone.CS_MODE_BIG_ENDIAN),
    # --- M680X ---
    ("M680X", capstone.CS_ARCH_M680X, "6301", capstone.CS_MODE_M680X_6301),
    ("M680X", capstone.CS_ARCH_M680X, "6309", capstone.CS_MODE_M680X_6309),
    ("M680X", capstone.CS_ARCH_M680X, "6800", capstone.CS_MODE_M680X_6800),
    ("M680X", capstone.CS_ARCH_M680X, "6801", capstone.CS_MODE_M680X_6801),
    ("M680X", capstone.CS_ARCH_M680X, "6805", capstone.CS_MODE_M680X_6805),
    ("M680X", capstone.CS_ARCH_M680X, "6808", capstone.CS_MODE_M680X_6808),
    ("M680X", capstone.CS_ARCH_M680X, "6809", capstone.CS_MODE_M680X_6809),
    ("M680X", capstone.CS_ARCH_M680X, "6811", capstone.CS_MODE_M680X_6811),
    ("M680X", capstone.CS_ARCH_M680X, "CPU12", capstone.CS_MODE_M680X_CPU12),
    ("M680X", capstone.CS_ARCH_M680X, "HCS08", capstone.CS_MODE_M680X_HCS08),
    # --- EVM ---
    ("EVM", capstone.CS_ARCH_EVM, "0", 0),
    # --- MOS65XX ---
    ("MOS65XX", capstone.CS_ARCH_MOS65XX, "6502", capstone.CS_MODE_MOS65XX_6502),
    ("MOS65XX", capstone.CS_ARCH_MOS65XX, "65C02", capstone.CS_MODE_MOS65XX_65C02),
    ("MOS65XX", capstone.CS_ARCH_MOS65XX, "W65C02", capstone.CS_MODE_MOS65XX_W65C02),
    ("MOS65XX", capstone.CS_ARCH_MOS65XX, "65816", capstone.CS_MODE_MOS65XX_65816),
    (
        "MOS65XX",
        capstone.CS_ARCH_MOS65XX,
        "65816_LONG_M",
        capstone.CS_MODE_MOS65XX_65816_LONG_M,
    ),
    (
        "MOS65XX",
        capstone.CS_ARCH_MOS65XX,
        "65816_LONG_X",
        capstone.CS_MODE_MOS65XX_65816_LONG_X,
    ),
    (
        "MOS65XX",
        capstone.CS_ARCH_MOS65XX,
        "65816_LONG_MX",
        capstone.CS_MODE_MOS65XX_65816_LONG_MX,
    ),
    # --- WASM ---
    ("WASM", capstone.CS_ARCH_WASM, "0", 0),
    # --- BPF ---
    ("BPF", capstone.CS_ARCH_BPF, "CLASSIC", capstone.CS_MODE_BPF_CLASSIC),
    ("BPF", capstone.CS_ARCH_BPF, "EXTENDED", capstone.CS_MODE_BPF_EXTENDED),
    (
        "BPF",
        capstone.CS_ARCH_BPF,
        "CLASSIC (BE)",
        capstone.CS_MODE_BPF_CLASSIC | capstone.CS_MODE_BIG_ENDIAN,
    ),
    (
        "BPF",
        capstone.CS_ARCH_BPF,
        "EXTENDED (BE)",
        capstone.CS_MODE_BPF_EXTENDED | capstone.CS_MODE_BIG_ENDIAN,
    ),
    # --- RISCV ---
    ("RISCV", capstone.CS_ARCH_RISCV, "RISCV32", capstone.CS_MODE_RISCV32),
    ("RISCV", capstone.CS_ARCH_RISCV, "RISCV64", capstone.CS_MODE_RISCV64),
    (
        "RISCV",
        capstone.CS_ARCH_RISCV,
        "RISCV32|RISCVC",
        capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC,
    ),
    (
        "RISCV",
        capstone.CS_ARCH_RISCV,
        "RISCV64|RISCVC",
        capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
    ),
    # --- SH ---
    ("SH", capstone.CS_ARCH_SH, "SH2", capstone.CS_MODE_SH2),
    ("SH", capstone.CS_ARCH_SH, "SH2A", capstone.CS_MODE_SH2A),
    ("SH", capstone.CS_ARCH_SH, "SH3", capstone.CS_MODE_SH3),
    ("SH", capstone.CS_ARCH_SH, "SH4", capstone.CS_MODE_SH4),
    ("SH", capstone.CS_ARCH_SH, "SH4A", capstone.CS_MODE_SH4A),
    (
        "SH",
        capstone.CS_ARCH_SH,
        "SH4A|SHFPU",
        capstone.CS_MODE_SH4A | capstone.CS_MODE_SHFPU,
    ),
    (
        "SH",
        capstone.CS_ARCH_SH,
        "SH2A|SHDSP",
        capstone.CS_MODE_SH2A | capstone.CS_MODE_SHDSP,
    ),
    (
        "SH",
        capstone.CS_ARCH_SH,
        "SH4 (BE)",
        capstone.CS_MODE_SH4 | capstone.CS_MODE_BIG_ENDIAN,
    ),
    # --- TRICORE ---
    ("TRICORE", capstone.CS_ARCH_TRICORE, "110", capstone.CS_MODE_TRICORE_110),
    ("TRICORE", capstone.CS_ARCH_TRICORE, "120", capstone.CS_MODE_TRICORE_120),
    ("TRICORE", capstone.CS_ARCH_TRICORE, "130", capstone.CS_MODE_TRICORE_130),
    ("TRICORE", capstone.CS_ARCH_TRICORE, "131", capstone.CS_MODE_TRICORE_131),
    ("TRICORE", capstone.CS_ARCH_TRICORE, "160", capstone.CS_MODE_TRICORE_160),
    ("TRICORE", capstone.CS_ARCH_TRICORE, "161", capstone.CS_MODE_TRICORE_161),
    ("TRICORE", capstone.CS_ARCH_TRICORE, "162", capstone.CS_MODE_TRICORE_162),
]

# ============================================================================
# KEYSTONE (v0.9.2 — no RISCV support)
# ============================================================================

KEYSTONE_COMBOS = [
    # --- ARM ---
    ("ARM", keystone.KS_ARCH_ARM, "ARM (LE)", keystone.KS_MODE_ARM),
    ("ARM", keystone.KS_ARCH_ARM, "THUMB (LE)", keystone.KS_MODE_THUMB),
    (
        "ARM",
        keystone.KS_ARCH_ARM,
        "ARM|V8 (LE)",
        keystone.KS_MODE_ARM | keystone.KS_MODE_V8,
    ),
    (
        "ARM",
        keystone.KS_ARCH_ARM,
        "THUMB|V8 (LE)",
        keystone.KS_MODE_THUMB | keystone.KS_MODE_V8,
    ),
    (
        "ARM",
        keystone.KS_ARCH_ARM,
        "ARM (BE)",
        keystone.KS_MODE_ARM | keystone.KS_MODE_BIG_ENDIAN,
    ),
    (
        "ARM",
        keystone.KS_ARCH_ARM,
        "THUMB (BE)",
        keystone.KS_MODE_THUMB | keystone.KS_MODE_BIG_ENDIAN,
    ),
    (
        "ARM",
        keystone.KS_ARCH_ARM,
        "ARM|V8 (BE)",
        keystone.KS_MODE_ARM | keystone.KS_MODE_V8 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    (
        "ARM",
        keystone.KS_ARCH_ARM,
        "THUMB|V8 (BE)",
        keystone.KS_MODE_THUMB | keystone.KS_MODE_V8 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    ("ARM", keystone.KS_ARCH_ARM, "V8 alone", keystone.KS_MODE_V8),
    # --- ARM64 ---
    ("ARM64", keystone.KS_ARCH_ARM64, "LE", 0),
    ("ARM64", keystone.KS_ARCH_ARM64, "BE", keystone.KS_MODE_BIG_ENDIAN),
    # --- MIPS ---
    (
        "MIPS",
        keystone.KS_ARCH_MIPS,
        "MIPS32 (BE)",
        keystone.KS_MODE_MIPS32 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    (
        "MIPS",
        keystone.KS_ARCH_MIPS,
        "MIPS64 (BE)",
        keystone.KS_MODE_MIPS64 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    ("MIPS", keystone.KS_ARCH_MIPS, "MIPS32 (LE)", keystone.KS_MODE_MIPS32),
    ("MIPS", keystone.KS_ARCH_MIPS, "MIPS64 (LE)", keystone.KS_MODE_MIPS64),
    ("MIPS", keystone.KS_ARCH_MIPS, "MICRO", keystone.KS_MODE_MICRO),
    ("MIPS", keystone.KS_ARCH_MIPS, "MIPS3", keystone.KS_MODE_MIPS3),
    ("MIPS", keystone.KS_ARCH_MIPS, "MIPS32R6", keystone.KS_MODE_MIPS32R6),
    # --- X86 ---
    ("X86", keystone.KS_ARCH_X86, "16", keystone.KS_MODE_16),
    ("X86", keystone.KS_ARCH_X86, "32", keystone.KS_MODE_32),
    ("X86", keystone.KS_ARCH_X86, "64", keystone.KS_MODE_64),
    # --- PPC ---
    (
        "PPC",
        keystone.KS_ARCH_PPC,
        "PPC32 (BE)",
        keystone.KS_MODE_PPC32 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    (
        "PPC",
        keystone.KS_ARCH_PPC,
        "PPC64 (BE)",
        keystone.KS_MODE_PPC64 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    ("PPC", keystone.KS_ARCH_PPC, "PPC64 (LE)", keystone.KS_MODE_PPC64),
    ("PPC", keystone.KS_ARCH_PPC, "PPC32 (LE)", keystone.KS_MODE_PPC32),
    ("PPC", keystone.KS_ARCH_PPC, "QPX", keystone.KS_MODE_QPX),
    # --- SPARC ---
    (
        "SPARC",
        keystone.KS_ARCH_SPARC,
        "SPARC32 (BE)",
        keystone.KS_MODE_SPARC32 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    (
        "SPARC",
        keystone.KS_ARCH_SPARC,
        "SPARC64 (BE)",
        keystone.KS_MODE_SPARC64 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    ("SPARC", keystone.KS_ARCH_SPARC, "SPARC32 (LE)", keystone.KS_MODE_SPARC32),
    ("SPARC", keystone.KS_ARCH_SPARC, "SPARC64 (LE)", keystone.KS_MODE_SPARC64),
    ("SPARC", keystone.KS_ARCH_SPARC, "V9 alone", keystone.KS_MODE_V9),
    (
        "SPARC",
        keystone.KS_ARCH_SPARC,
        "SPARC32|V9 (BE)",
        keystone.KS_MODE_SPARC32 | keystone.KS_MODE_V9 | keystone.KS_MODE_BIG_ENDIAN,
    ),
    # --- SYSTEMZ ---
    ("SYSTEMZ", keystone.KS_ARCH_SYSTEMZ, "BE", keystone.KS_MODE_BIG_ENDIAN),
    ("SYSTEMZ", keystone.KS_ARCH_SYSTEMZ, "LE", 0),
    # --- HEXAGON ---
    ("HEXAGON", keystone.KS_ARCH_HEXAGON, "BE", keystone.KS_MODE_BIG_ENDIAN),
    ("HEXAGON", keystone.KS_ARCH_HEXAGON, "LE", 0),
    # --- EVM ---
    ("EVM", keystone.KS_ARCH_EVM, "0", 0),
]

# ============================================================================
# UNICORN (v2.1.0)
# ============================================================================

UNICORN_COMBOS = [
    # --- ARM ---
    ("ARM", unicorn.UC_ARCH_ARM, "ARM (LE)", 0),
    ("ARM", unicorn.UC_ARCH_ARM, "THUMB", unicorn.UC_MODE_THUMB),
    (
        "ARM",
        unicorn.UC_ARCH_ARM,
        "THUMB|MCLASS",
        unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS,
    ),
    ("ARM", unicorn.UC_ARCH_ARM, "ARM (BE)", unicorn.UC_MODE_BIG_ENDIAN),
    (
        "ARM",
        unicorn.UC_ARCH_ARM,
        "THUMB (BE)",
        unicorn.UC_MODE_THUMB | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    ("ARM", unicorn.UC_ARCH_ARM, "ARM926", unicorn.UC_MODE_ARM926),
    ("ARM", unicorn.UC_ARCH_ARM, "ARM946", unicorn.UC_MODE_ARM946),
    ("ARM", unicorn.UC_ARCH_ARM, "ARM1176", unicorn.UC_MODE_ARM1176),
    ("ARM", unicorn.UC_ARCH_ARM, "ARMBE8", unicorn.UC_MODE_ARMBE8),
    ("ARM", unicorn.UC_ARCH_ARM, "V8", unicorn.UC_MODE_V8),
    (
        "ARM",
        unicorn.UC_ARCH_ARM,
        "THUMB|ARM926",
        unicorn.UC_MODE_THUMB | unicorn.UC_MODE_ARM926,
    ),
    (
        "ARM",
        unicorn.UC_ARCH_ARM,
        "THUMB|MCLASS|BE",
        unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    # --- ARM64 ---
    ("ARM64", unicorn.UC_ARCH_ARM64, "LE", 0),
    ("ARM64", unicorn.UC_ARCH_ARM64, "BE", unicorn.UC_MODE_BIG_ENDIAN),
    # --- MIPS ---
    ("MIPS", unicorn.UC_ARCH_MIPS, "MIPS32", unicorn.UC_MODE_MIPS32),
    ("MIPS", unicorn.UC_ARCH_MIPS, "MIPS64", unicorn.UC_MODE_MIPS64),
    (
        "MIPS",
        unicorn.UC_ARCH_MIPS,
        "MIPS32 (BE)",
        unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    (
        "MIPS",
        unicorn.UC_ARCH_MIPS,
        "MIPS64 (BE)",
        unicorn.UC_MODE_MIPS64 | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    ("MIPS", unicorn.UC_ARCH_MIPS, "MICRO", unicorn.UC_MODE_MICRO),
    ("MIPS", unicorn.UC_ARCH_MIPS, "MIPS3", unicorn.UC_MODE_MIPS3),
    ("MIPS", unicorn.UC_ARCH_MIPS, "MIPS32R6", unicorn.UC_MODE_MIPS32R6),
    # --- X86 ---
    ("X86", unicorn.UC_ARCH_X86, "16", unicorn.UC_MODE_16),
    ("X86", unicorn.UC_ARCH_X86, "32", unicorn.UC_MODE_32),
    ("X86", unicorn.UC_ARCH_X86, "64", unicorn.UC_MODE_64),
    # --- PPC ---
    (
        "PPC",
        unicorn.UC_ARCH_PPC,
        "PPC32 (BE)",
        unicorn.UC_MODE_PPC32 | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    (
        "PPC",
        unicorn.UC_ARCH_PPC,
        "PPC64 (BE)",
        unicorn.UC_MODE_PPC64 | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    ("PPC", unicorn.UC_ARCH_PPC, "PPC32 (LE)", unicorn.UC_MODE_PPC32),
    ("PPC", unicorn.UC_ARCH_PPC, "QPX", unicorn.UC_MODE_QPX),
    ("PPC", unicorn.UC_ARCH_PPC, "BE only", unicorn.UC_MODE_BIG_ENDIAN),
    # --- SPARC ---
    (
        "SPARC",
        unicorn.UC_ARCH_SPARC,
        "SPARC32 (BE)",
        unicorn.UC_MODE_SPARC32 | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    (
        "SPARC",
        unicorn.UC_ARCH_SPARC,
        "SPARC64 (BE)",
        unicorn.UC_MODE_SPARC64 | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    ("SPARC", unicorn.UC_ARCH_SPARC, "SPARC32 (LE)", unicorn.UC_MODE_SPARC32),
    ("SPARC", unicorn.UC_ARCH_SPARC, "V9", unicorn.UC_MODE_V9),
    ("SPARC", unicorn.UC_ARCH_SPARC, "BE only", unicorn.UC_MODE_BIG_ENDIAN),
    # --- M68K ---
    ("M68K", unicorn.UC_ARCH_M68K, "BE", unicorn.UC_MODE_BIG_ENDIAN),
    ("M68K", unicorn.UC_ARCH_M68K, "LE", 0),
    # --- RISCV ---
    ("RISCV", unicorn.UC_ARCH_RISCV, "RISCV32", unicorn.UC_MODE_RISCV32),
    ("RISCV", unicorn.UC_ARCH_RISCV, "RISCV64", unicorn.UC_MODE_RISCV64),
    (
        "RISCV",
        unicorn.UC_ARCH_RISCV,
        "RISCV32 (BE)",
        unicorn.UC_MODE_RISCV32 | unicorn.UC_MODE_BIG_ENDIAN,
    ),
    # --- S390X ---
    ("S390X", unicorn.UC_ARCH_S390X, "BE", unicorn.UC_MODE_BIG_ENDIAN),
    ("S390X", unicorn.UC_ARCH_S390X, "LE", 0),
    # --- TRICORE ---
    ("TRICORE", unicorn.UC_ARCH_TRICORE, "LE", 0),
    ("TRICORE", unicorn.UC_ARCH_TRICORE, "BE", unicorn.UC_MODE_BIG_ENDIAN),
]


# ============================================================================
# RUNNER
# ============================================================================


def run_combos(lib_name, combos, factory):
    ok = 0
    fail = 0
    results = []
    for arch_name, arch, mode_name, mode in combos:
        try:
            _ = factory(arch, mode)
            results.append((arch_name, mode_name, mode, "OK", ""))
            ok += 1
        except Exception as e:
            err_msg = str(e).strip()
            results.append((arch_name, mode_name, mode, "FAIL", err_msg))
            fail += 1
    return results, ok, fail


def print_table(lib_name, results, ok, fail):
    print(f"\n{'=' * 80}")
    print(f" {lib_name}  (v{get_version(lib_name)})")
    print(f" {ok} OK, {fail} FAIL")
    print(f"{'=' * 80}")
    print(f"  {'Arch':<14} {'Mode':<28} {'Value':<12} {'Result':<6} Error")
    print(f"  {'-' * 13:<14} {'-' * 27:<28} {'-' * 11:<12} {'-' * 5:<6} {'-' * 20}")
    for arch_name, mode_name, mode_val, status, err in results:
        marker = "OK" if status == "OK" else "FAIL"
        print(f"  {arch_name:<14} {mode_name:<28} {mode_val:<12} {marker:<6} {err}")


def get_version(lib_name):
    if lib_name == "CAPSTONE":
        return capstone.__version__
    elif lib_name == "KEYSTONE":
        return keystone.__version__
    elif lib_name == "UNICORN":
        return unicorn.__version__


def main():
    all_fail = 0

    results, ok, fail = run_combos("CAPSTONE", CAPSTONE_COMBOS, capstone.Cs)
    print_table("CAPSTONE", results, ok, fail)
    all_fail += fail

    results, ok, fail = run_combos("KEYSTONE", KEYSTONE_COMBOS, keystone.Ks)
    print_table("KEYSTONE", results, ok, fail)
    all_fail += fail

    results, ok, fail = run_combos("UNICORN", UNICORN_COMBOS, unicorn.Uc)
    print_table("UNICORN", results, ok, fail)
    all_fail += fail

    print(f"\n{'=' * 80}")
    if all_fail:
        print(f" TOTAL: {all_fail} combinations failed")
    else:
        print(" ALL COMBINATIONS PASSED")
    print(f"{'=' * 80}")
    return 1 if all_fail else 0


if __name__ == "__main__":
    sys.exit(main())
