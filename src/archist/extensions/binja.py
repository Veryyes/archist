from __future__ import annotations

import sys
import typing

import keystone
import capstone
import unicorn

from . import safe_kwargs, safe_mode, BinArchInfo
import archist

if typing.TYPE_CHECKING:
    import binaryninja


# Map Binary Ninja bv.arch.name strings to (Arch, Mode, kwargs).
# Endianness is handled separately via bv.endianness.
_BINJA_ARCH_MAP: typing.Dict[
    str,
    typing.Tuple[
        typing.Type[archist.core.Arch], archist.core.Mode, typing.Dict[str, bool]
    ],
] = {
    # x86
    "x86": (archist.X86, archist.X86.Modes._32, {}),
    "x86_64": (archist.X86, archist.X86.Modes._64, {}),
    # ARM
    "armv7": (archist.ARM, archist.ARM.Modes.arm, {}),
    "armv7eb": (archist.ARM, archist.ARM.Modes.arm, {}),
    "thumb2": (archist.ARM, archist.ARM.Modes.thumb, {}),
    "thumb2eb": (archist.ARM, archist.ARM.Modes.thumb, {}),
    "aarch64": (archist.ARM64, archist.NO_MODES, {}),
    # MIPS
    "mips32": (archist.MIPS, archist.MIPS.Modes.mips32, {}),
    "mips32eb": (archist.MIPS, archist.MIPS.Modes.mips32, {}),
    "mips64": (archist.MIPS, archist.MIPS.Modes.mips64, {}),
    "mips64eb": (archist.MIPS, archist.MIPS.Modes.mips64, {}),
    # PowerPC
    "ppc": (archist.PPC, archist.PPC.Modes.ppc32, {}),
    "ppc64": (archist.PPC, archist.PPC.Modes.ppc64, {}),
    # RISC-V
    "rv32gc": (archist.RISCV, archist.RISCV.Modes.riscv32, {}),
    "rv64gc": (archist.RISCV, archist.RISCV.Modes.riscv64, {}),
    # Others
    "tricore": (archist.TRICORE, archist.NO_MODES, {}),
}


def _from_binja(bv: binaryninja.BinaryView) -> BinArchInfo:
    try:
        import binaryninja.enums
    except ImportError as e:
        print(
            f"{e} Could not import binaryninja. Do you have the API installed? EXITING"
        )
        sys.exit(1)

    arch_name = bv.arch.name
    endian = (
        archist.LITTLE_ENDIAN
        if bv.endianness == binaryninja.enums.Endianness.LittleEndian
        else archist.BIG_ENDIAN
    )

    entry = _BINJA_ARCH_MAP.get(arch_name)
    if entry is None:
        raise ValueError(f"Unsupported Binary Ninja architecture: {arch_name}")

    arch, mode, kwargs = entry
    return BinArchInfo(arch, endian, mode, kwargs)


def Ks(bv: binaryninja.BinaryView) -> keystone.Ks:
    info = _from_binja(bv)
    return info.arch._Ks(
        info.endian, safe_mode(info.mode, "ks"), **safe_kwargs(info, "ks")
    )


def Cs(bv: binaryninja.BinaryView) -> capstone.Cs:
    info = _from_binja(bv)
    return info.arch._Cs(
        info.endian, safe_mode(info.mode, "cs"), **safe_kwargs(info, "cs")
    )


def Uc(bv: binaryninja.BinaryView) -> unicorn.Uc:
    info = _from_binja(bv)
    return info.arch._Uc(
        info.endian, safe_mode(info.mode, "uc"), **safe_kwargs(info, "uc")
    )
