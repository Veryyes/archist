import typing

import lief
import keystone
import capstone
import unicorn

from . import safe_kwargs, safe_mode, resolve_elf_arch, ELFArchInfo
import archist


# Map LIEF ARCH enums to pyelftools e_machine strings
_LIEF_ARCH_TO_EM: typing.Dict[lief.ELF.ARCH, str] = {
    lief.ELF.ARCH.I386: "EM_386",
    lief.ELF.ARCH.X86_64: "EM_X86_64",
    lief.ELF.ARCH.ARM: "EM_ARM",
    lief.ELF.ARCH.AARCH64: "EM_AARCH64",
    lief.ELF.ARCH.MIPS: "EM_MIPS",
    lief.ELF.ARCH.PPC: "EM_PPC",
    lief.ELF.ARCH.PPC64: "EM_PPC64",
    lief.ELF.ARCH.SPARC: "EM_SPARC",
    lief.ELF.ARCH.SPARCV9: "EM_SPARCV9",
    lief.ELF.ARCH.RISCV: "EM_RISCV",
    lief.ELF.ARCH.S390: "EM_S390",
    lief.ELF.ARCH.SH: "EM_SH",
    lief.ELF.ARCH.M68K: "EM_68K",
    lief.ELF.ARCH.TRICORE: "EM_TRICORE",
}


def _from_lief(binary: lief.ELF.Binary) -> ELFArchInfo:
    machine = _LIEF_ARCH_TO_EM.get(binary.header.machine_type)
    if machine is None:
        raise ValueError(f"Unsupported ELF machine type: {binary.header.machine_type}")

    return resolve_elf_arch(
        machine=machine,
        e_flags=binary.header.processor_flag,
        elfclass=64
        if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64
        else 32,
        endian=archist.LITTLE_ENDIAN
        if binary.header.identity_data == lief.ELF.Header.ELF_DATA.LSB
        else archist.BIG_ENDIAN,
        entrypoint=binary.header.entrypoint,
    )


def Ks(binary: lief.ELF.Binary) -> keystone.Ks:
    info = _from_lief(binary)
    return info.arch._Ks(
        info.endian, safe_mode(info.mode, "ks"), **safe_kwargs(info, "ks")
    )


def Cs(binary: lief.ELF.Binary) -> capstone.Cs:
    info = _from_lief(binary)
    return info.arch._Cs(
        info.endian, safe_mode(info.mode, "cs"), **safe_kwargs(info, "cs")
    )


def Uc(binary: lief.ELF.Binary) -> unicorn.Uc:
    info = _from_lief(binary)
    return info.arch._Uc(
        info.endian, safe_mode(info.mode, "uc"), **safe_kwargs(info, "uc")
    )
