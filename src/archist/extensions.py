import typing
import dataclasses

import elftools.elf.elffile
import elftools.elf.constants
import keystone
import capstone
import unicorn

import archist

# ELF e_flags not in pyelftools
EF_MIPS_ARCH_32R6 = 0x90000000
EF_MIPS_MICROMIPS = 0x02000000
EF_SPARC_V9 = 0x100
EF_SH_MACH_MASK = 0x1F


@dataclasses.dataclass
class ELFArchInfo:
    arch: typing.Type[archist.core.Arch]
    endian: archist.core.Endian
    mode: archist.core.Mode
    kwargs: typing.Dict[str, bool]


def _from_pyelftools(elf: elftools.elf.elffile.ELFFile) -> ELFArchInfo:
    machine = elf.header.e_machine
    e_flags = elf.header.e_flags
    elfclass = elf.elfclass  # 32 or 64

    endian = archist.LITTLE_ENDIAN if elf.little_endian else archist.BIG_ENDIAN

    match machine:
        # x86 family
        case "EM_386":
            return ELFArchInfo(archist.X86, endian, archist.X86.Modes._32, {})
        case "EM_X86_64":
            return ELFArchInfo(archist.X86, endian, archist.X86.Modes._64, {})

        # ARM
        case "EM_ARM":
            kwargs: dict[str, bool] = {"v8": False}

            # Detect Thumb via entry point bit 0
            if elf.header.e_entry & 1:
                mode = archist.ARM.Modes.thumb
            else:
                mode = archist.ARM.Modes.arm

            return ELFArchInfo(archist.ARM, endian, mode, kwargs)

        case "EM_AARCH64":
            return ELFArchInfo(archist.ARM64, endian, archist.NO_MODES, {})

        # MIPS
        case "EM_MIPS":
            if elfclass == 64:
                mode = archist.MIPS.Modes.mips64
            else:
                mode = archist.MIPS.Modes.mips32

            kwargs = {
                "micro": bool(e_flags & EF_MIPS_MICROMIPS),
                "mips32r6": (e_flags & elftools.elf.constants.E_FLAGS.EF_MIPS_ARCH)
                == EF_MIPS_ARCH_32R6,
            }
            return ELFArchInfo(archist.MIPS, endian, mode, kwargs)

        # PowerPC
        case "EM_PPC":
            return ELFArchInfo(archist.PPC, endian, archist.PPC.Modes.ppc32, {})
        case "EM_PPC64":
            return ELFArchInfo(archist.PPC, endian, archist.PPC.Modes.ppc64, {})

        # SPARC
        case "EM_SPARC":
            return ELFArchInfo(
                archist.SPARC,
                endian,
                archist.SPARC.Modes.sparc32,
                {
                    "v9": bool(e_flags & EF_SPARC_V9),
                },
            )
        case "EM_SPARCV9":
            return ELFArchInfo(
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
            return ELFArchInfo(archist.RISCV, endian, mode, {})

        # Others
        case "EM_S390":
            return ELFArchInfo(archist.S390X, endian, archist.NO_MODES, {})
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
            return ELFArchInfo(archist.SH, endian, mode, {})
        case "EM_68K":
            return ELFArchInfo(archist.M68K, endian, archist.NO_MODES, {})
        case "EM_TRICORE":
            return ELFArchInfo(archist.TRICORE, endian, archist.NO_MODES, {})

        case _:
            raise ValueError(f"Unsupported ELF machine type: {machine}")


def _safe_mode(mode: archist.core.Mode, backend: str) -> archist.core.Mode:
    """Return NO_MODES if the mode lacks support for the given backend."""
    if getattr(mode, backend) is None:
        return archist.NO_MODES
    return mode


def Ks_pyelftools(elf: elftools.elf.elffile.ELFFile) -> keystone.Ks:
    info = _from_pyelftools(elf)
    mode = _safe_mode(info.mode, "ks")
    kwargs = (
        {
            k: v
            for k, v in info.kwargs.items()
            if _safe_mode(info.arch._mode_lookup(k), "ks").ks is not None
        }
        if info.kwargs
        else {}
    )
    return info.arch._Ks(info.endian, mode, **kwargs)


def Cs_pyelftools(elf: elftools.elf.elffile.ELFFile) -> capstone.Cs:
    info = _from_pyelftools(elf)
    mode = _safe_mode(info.mode, "cs")
    kwargs = (
        {
            k: v
            for k, v in info.kwargs.items()
            if _safe_mode(info.arch._mode_lookup(k), "cs").cs is not None
        }
        if info.kwargs
        else {}
    )
    return info.arch._Cs(info.endian, mode, **kwargs)


def Uc_pyelftools(elf: elftools.elf.elffile.ELFFile) -> unicorn.Uc:
    info = _from_pyelftools(elf)
    mode = _safe_mode(info.mode, "uc")
    kwargs = (
        {
            k: v
            for k, v in info.kwargs.items()
            if _safe_mode(info.arch._mode_lookup(k), "uc").uc is not None
        }
        if info.kwargs
        else {}
    )
    return info.arch._Uc(info.endian, mode, **kwargs)
