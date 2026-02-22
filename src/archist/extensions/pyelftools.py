import elftools.elf.elffile
import elftools.elf.constants
import keystone
import capstone
import unicorn

from . import safe_kwargs, safe_mode, resolve_elf_arch, ELFArchInfo
import archist


def _from_pyelftools(elf: elftools.elf.elffile.ELFFile) -> ELFArchInfo:
    return resolve_elf_arch(
        machine=elf.header.e_machine,
        e_flags=elf.header.e_flags,
        elfclass=elf.elfclass,
        endian=archist.LITTLE_ENDIAN if elf.little_endian else archist.BIG_ENDIAN,
        entrypoint=elf.header.e_entry,
    )


def Ks(elf: elftools.elf.elffile.ELFFile) -> keystone.Ks:
    info = _from_pyelftools(elf)
    return info.arch._Ks(
        info.endian, safe_mode(info.mode, "ks"), **safe_kwargs(info, "ks")
    )


def Cs(elf: elftools.elf.elffile.ELFFile) -> capstone.Cs:
    info = _from_pyelftools(elf)
    return info.arch._Cs(
        info.endian, safe_mode(info.mode, "cs"), **safe_kwargs(info, "cs")
    )


def Uc(elf: elftools.elf.elffile.ELFFile) -> unicorn.Uc:
    info = _from_pyelftools(elf)
    return info.arch._Uc(
        info.endian, safe_mode(info.mode, "uc"), **safe_kwargs(info, "uc")
    )
