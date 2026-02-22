from __future__ import annotations

import typing

import keystone
import capstone
import unicorn

from . import safe_kwargs, safe_mode, BinArchInfo
import archist

if typing.TYPE_CHECKING:
    import ghidra.program.model.listing  # type: ignore[import-not-found]


# Ghidra LanguageID format: "processor:endianness:size:variant"
# e.g. "ARM:LE:32:v8", "x86:LE:64:default", "MIPS:BE:32:default"

# Map Ghidra processor names to archist Arch classes
_GHIDRA_PROCESSOR_MAP: typing.Dict[
    str,
    typing.Type[archist.core.Arch],
] = {
    "ARM": archist.ARM,
    "AARCH64": archist.ARM64,
    "MIPS": archist.MIPS,
    "x86": archist.X86,
    "PowerPC": archist.PPC,
    "Sparc": archist.SPARC,
    "sparc": archist.SPARC,
    "RISCV": archist.RISCV,
    "68000": archist.M68K,
    "SuperH": archist.SH,
    "SuperH4": archist.SH,
    "s390x": archist.S390X,
    "tricore": archist.TRICORE,
}

# Map (processor, size, variant) to archist modes and kwargs.
# Entries are (mode, kwargs) tuples.
# None means: derive mode from size alone (handled in _resolve_mode).
_GHIDRA_VARIANT_MAP: typing.Dict[
    typing.Tuple[str, int, str],
    typing.Tuple[archist.core.Mode, typing.Dict[str, bool]],
] = {
    # ARM variants (v8 kwarg left False — unicorn rejects UC_MODE_V8)
    ("ARM", 32, "v8"): (archist.ARM.Modes.arm, {"v8": False}),
    ("ARM", 32, "v8T"): (archist.ARM.Modes.thumb, {"v8": False}),
    ("ARM", 32, "Thumb"): (archist.ARM.Modes.thumb, {}),
    # MIPS variants
    ("MIPS", 32, "micro"): (archist.MIPS.Modes.mips32, {"micro": True}),
    ("MIPS", 64, "micro"): (archist.MIPS.Modes.mips64, {"micro": True}),
    ("MIPS", 32, "R6"): (archist.MIPS.Modes.mips32, {"mips32r6": True}),
    # SPARC variants (Ghidra uses both "Sparc" and "sparc")
    ("Sparc", 64, "default"): (archist.SPARC.Modes.sparc64, {}),
    ("Sparc", 32, "default"): (archist.SPARC.Modes.sparc32, {}),
    ("Sparc", 32, "V9"): (archist.SPARC.Modes.sparc32, {"v9": True}),
    ("sparc", 64, "default"): (archist.SPARC.Modes.sparc64, {}),
    ("sparc", 32, "default"): (archist.SPARC.Modes.sparc32, {}),
    ("sparc", 32, "V9"): (archist.SPARC.Modes.sparc32, {"v9": True}),
}


def _resolve_mode(
    processor: str,
    size: int,
    variant: str,
) -> typing.Tuple[archist.core.Mode, typing.Dict[str, bool]]:
    key = (processor, size, variant)
    if key in _GHIDRA_VARIANT_MAP:
        return _GHIDRA_VARIANT_MAP[key]

    match processor:
        case "ARM":
            return (archist.ARM.Modes.arm, {})
        case "AARCH64":
            return (archist.NO_MODES, {})
        case "MIPS":
            if size == 64:
                return (archist.MIPS.Modes.mips64, {})
            return (archist.MIPS.Modes.mips32, {})
        case "x86":
            if size == 64:
                return (archist.X86.Modes._64, {})
            if size == 16:
                return (archist.X86.Modes._16, {})
            return (archist.X86.Modes._32, {})
        case "PowerPC":
            if size == 64:
                return (archist.PPC.Modes.ppc64, {})
            return (archist.PPC.Modes.ppc32, {})
        case "Sparc" | "sparc":
            if size == 64:
                return (archist.SPARC.Modes.sparc64, {})
            return (archist.SPARC.Modes.sparc32, {})
        case "RISCV":
            if size == 64:
                return (archist.RISCV.Modes.riscv64, {})
            return (archist.RISCV.Modes.riscv32, {})
        case "68000":
            return (archist.NO_MODES, {})
        case "SuperH" | "SuperH4":
            variant_lower = variant.lower()
            sh_variant_map = {
                "sh-2": archist.SH.Modes.sh2,
                "sh-2a": archist.SH.Modes.sh2a,
                "sh-3": archist.SH.Modes.sh3,
                "sh-4": archist.SH.Modes.sh4,
                "default": archist.SH.Modes.sh4,
            }
            mode = sh_variant_map.get(variant_lower, archist.SH.Modes.sh4)
            return (mode, {})
        case "s390x":
            return (archist.NO_MODES, {})
        case "tricore":
            return (archist.NO_MODES, {})
        case _:
            raise ValueError(f"Unsupported Ghidra processor: {processor}")


def _from_ghidra(program: ghidra.program.model.listing.Program) -> BinArchInfo:
    lang = program.getLanguage()
    lang_id = lang.getLanguageID().toString()
    parts = lang_id.split(":")

    processor = parts[0]
    endian_str = parts[1]
    size = int(parts[2])
    variant = parts[3] if len(parts) > 3 else "default"

    arch = _GHIDRA_PROCESSOR_MAP.get(processor)
    if arch is None:
        raise ValueError(f"Unsupported Ghidra processor: {processor}")

    endian = archist.LITTLE_ENDIAN if endian_str == "LE" else archist.BIG_ENDIAN
    mode, kwargs = _resolve_mode(processor, size, variant)

    return BinArchInfo(arch, endian, mode, kwargs)


def Ks(program: ghidra.program.model.listing.Program) -> keystone.Ks:
    info = _from_ghidra(program)
    return info.arch._Ks(
        info.endian, safe_mode(info.mode, "ks"), **safe_kwargs(info, "ks")
    )


def Cs(program: ghidra.program.model.listing.Program) -> capstone.Cs:
    info = _from_ghidra(program)
    return info.arch._Cs(
        info.endian, safe_mode(info.mode, "cs"), **safe_kwargs(info, "cs")
    )


def Uc(program: ghidra.program.model.listing.Program) -> unicorn.Uc:
    info = _from_ghidra(program)
    return info.arch._Uc(
        info.endian, safe_mode(info.mode, "uc"), **safe_kwargs(info, "uc")
    )
