"""Arch and Mode generation logic."""

import re
import itertools
import typing
import dataclasses

import capstone
import keystone
import unicorn
import qiling.const

from util import getattr_regex, non_dunder_members, INT_CONSTS_LIBS
from regs import generate_registers


@dataclasses.dataclass
class ModeTemplate:
    name: str
    ks: str
    cs: str
    uc: str


@dataclasses.dataclass
class ArchTemplate:
    name: str
    ks: str
    cs: str
    uc: str
    ql: str
    modes: typing.List[str]
    registers: typing.List[str]


def generate_modes() -> typing.List[ModeTemplate]:
    # Group 1 => Library prefix (UC == Unicorn)
    # Group 2 => Arch name
    # Group 3 => Optional Variant
    var_pattern = re.compile(r"(\w\w)_MODE_((\w+)(\w+))?")
    all_consts = itertools.chain(
        *[getattr_regex(lib, var_pattern, group_no=2) for lib in INT_CONSTS_LIBS]
    )

    mode_names = set(all_consts)

    modes: typing.List[ModeTemplate] = list()
    for name in mode_names:
        if name in ["BIG_ENDIAN", "LITTLE_ENDIAN"]:
            continue

        m = ModeTemplate(
            name=f"_{name}" if not name.isidentifier() else name,
            ks=f"keystone.KS_MODE_{name}"
            if hasattr(keystone, f"KS_MODE_{name}")
            else "None",
            cs=f"capstone.CS_MODE_{name}"
            if hasattr(capstone, f"CS_MODE_{name}")
            else "None",
            uc=f"unicorn.UC_MODE_{name}"
            if hasattr(unicorn, f"UC_MODE_{name}")
            else "None",
        )
        modes.append(m)

    modes.sort(key=lambda m: m.name)
    return modes


def generate_arches(modes: typing.List[ModeTemplate]) -> typing.List[ArchTemplate]:
    # Group 1 => Library prefix (UC == Unicorn)
    # Group 2 => Arch name
    var_pattern = re.compile(r"(\w\w)_ARCH_(\w+)")
    all_consts = itertools.chain(
        *[getattr_regex(lib, var_pattern, group_no=2) for lib in INT_CONSTS_LIBS]
    )

    # Union of all arches supported by all 4 libaries
    arch_names = set(
        list(all_consts) + list(non_dunder_members(qiling.const.QL_ARCH).keys())
    )

    arches: typing.List[ArchTemplate] = list()
    for name in arch_names:
        a = ArchTemplate(
            name=name,
            ks=f"keystone.KS_ARCH_{name}"
            if hasattr(keystone, f"KS_ARCH_{name}")
            else "None",
            cs=f"capstone.CS_ARCH_{name}"
            if hasattr(capstone, f"CS_ARCH_{name}")
            else "None",
            uc=f"unicorn.UC_ARCH_{name}"
            if hasattr(unicorn, f"UC_ARCH_{name}")
            else "None",
            ql=f"qiling.const.QL_ARCH.{name}"
            if hasattr(qiling.const.QL_ARCH, name)
            else "None",
            modes=list(),
            registers=generate_registers(name),
        )
        for mode in filter(lambda m: a.name in m.name, modes):
            a.modes.append(mode.name)

        # Special Cases for Mode association with their respective architecture

        if name == "ARM64":
            # ARM64/aarch64 but *_MODE_ARM must still be used wth it
            a.modes.append("ARM")

        if name == "X86":
            a.modes += ["_16", "_32"]

        if name in ["x86", "PPC"]:
            a.modes.append("_64")

        if name == "ARM":
            a.modes += ["THUMB", "MCLASS", "V8"]

        if name == "MIPS":
            a.modes.append("MICRO")

        if name == "SPARC":
            a.modes.append("V9")

        if name == "PPC":
            a.modes += ["QPX", "SPE", "BOOKE", "PS"]

        # Architecture special casing
        # X86 64bit is selected by a mode. Qiling is the only one without the concept of a "mode"
        # So, we just set X8664 to X86, except for qiling and adjust the mode accordingly
        if name == "X8664":
            name = "X86"
            a.ks = (
                f"keystone.KS_ARCH_{name}"
                if hasattr(keystone, f"KS_ARCH_{name}")
                else "None"
            )
            a.cs = (
                f"capstone.CS_ARCH_{name}"
                if hasattr(capstone, f"CS_ARCH_{name}")
                else "None"
            )
            a.uc = (
                f"unicorn.UC_ARCH_{name}"
                if hasattr(unicorn, f"UC_ARCH_{name}")
                else "None"
            )
            a.modes.append("_64")

        arches.append(a)
    arches.sort(key=lambda a: a.name)
    return arches
