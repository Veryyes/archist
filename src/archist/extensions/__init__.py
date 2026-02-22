import typing
import dataclasses

import archist

# ELF e_flags constants not provided by pyelftools or LIEF
EF_MIPS_ARCH_32R6 = 0x90000000
EF_MIPS_MICROMIPS = 0x02000000
EF_MIPS_ARCH_MASK = 0xF0000000
EF_SPARC_V9 = 0x100
EF_SH_MACH_MASK = 0x1F


@dataclasses.dataclass
class BinArchInfo:
    arch: typing.Type[archist.core.Arch]
    endian: archist.core.Endian
    mode: archist.core.Mode
    kwargs: typing.Dict[str, bool]


def resolve_elf_arch(
    machine: str,
    e_flags: int,
    elfclass: int,
    endian: archist.core.Endian,
    entrypoint: int,
) -> BinArchInfo:
    match machine:
        # x86 family
        case "EM_386":
            return BinArchInfo(archist.X86, endian, archist.X86.Modes._32, {})
        case "EM_X86_64":
            return BinArchInfo(archist.X86, endian, archist.X86.Modes._64, {})

        # ARM
        case "EM_ARM":
            kwargs: dict[str, bool] = {"v8": False}

            # Detect Thumb via entry point bit 0
            if entrypoint & 1:
                mode = archist.ARM.Modes.thumb
            else:
                mode = archist.ARM.Modes.arm

            return BinArchInfo(archist.ARM, endian, mode, kwargs)

        case "EM_AARCH64":
            return BinArchInfo(archist.ARM64, endian, archist.NO_MODES, {})

        # MIPS
        case "EM_MIPS":
            if elfclass == 64:
                mode = archist.MIPS.Modes.mips64
            else:
                mode = archist.MIPS.Modes.mips32

            kwargs = {
                "micro": bool(e_flags & EF_MIPS_MICROMIPS),
                "mips32r6": (e_flags & EF_MIPS_ARCH_MASK) == EF_MIPS_ARCH_32R6,
            }
            return BinArchInfo(archist.MIPS, endian, mode, kwargs)

        # PowerPC
        case "EM_PPC":
            return BinArchInfo(archist.PPC, endian, archist.PPC.Modes.ppc32, {})
        case "EM_PPC64":
            return BinArchInfo(archist.PPC, endian, archist.PPC.Modes.ppc64, {})

        # SPARC
        case "EM_SPARC":
            return BinArchInfo(
                archist.SPARC,
                endian,
                archist.SPARC.Modes.sparc32,
                {
                    "v9": bool(e_flags & EF_SPARC_V9),
                },
            )
        case "EM_SPARCV9":
            return BinArchInfo(
                archist.SPARC,
                endian,
                archist.SPARC.Modes.sparc64,
                {},
            )

        # RISC-V
        case "EM_RISCV":
            if elfclass == 64:
                mode = archist.RISCV.Modes.riscv64
            else:
                mode = archist.RISCV.Modes.riscv32
            return BinArchInfo(archist.RISCV, endian, mode, {})

        # Others
        case "EM_S390":
            return BinArchInfo(archist.S390X, endian, archist.NO_MODES, {})
        case "EM_SH":
            sh_mach = e_flags & EF_SH_MACH_MASK
            sh_mode_map = {
                0x02: archist.SH.Modes.sh2,
                0x03: archist.SH.Modes.sh3,
                0x09: archist.SH.Modes.sh4,
                0x0B: archist.SH.Modes.sh4a,
                0x0D: archist.SH.Modes.sh2a,
            }
            mode = sh_mode_map.get(sh_mach, archist.SH.Modes.sh4)
            return BinArchInfo(archist.SH, endian, mode, {})
        case "EM_68K":
            return BinArchInfo(archist.M68K, endian, archist.NO_MODES, {})
        case "EM_TRICORE":
            return BinArchInfo(archist.TRICORE, endian, archist.NO_MODES, {})

        case _:
            raise ValueError(f"Unsupported ELF machine type: {machine}")


def safe_mode(mode: archist.core.Mode, backend: str) -> archist.core.Mode:
    """Return NO_MODES if the mode lacks support for the given backend."""
    if getattr(mode, backend) is None:
        return archist.NO_MODES
    return mode


def safe_kwargs(info: BinArchInfo, backend: str) -> typing.Dict[str, bool]:
    """Filter kwargs to only include modes supported by the given backend."""
    if not info.kwargs:
        return {}
    return {
        k: v
        for k, v in info.kwargs.items()
        if safe_mode(info.arch._mode_lookup(k), backend) is not archist.NO_MODES
    }
