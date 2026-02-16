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


def int_str_sorted(items):
    """Sort a list of ints and str, and place the ints at the front"""
    ints = sorted(x for x in items if isinstance(x, int))
    strs = sorted(x for x in items if isinstance(x, str))
    return ints + strs


@dataclasses.dataclass
class ModeTemplate:
    name: str
    ks: str
    cs: str
    uc: str
    aliases: typing.List[str | int] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ArchTemplate:
    name: str
    ks: str
    cs: str
    uc: str
    ql: str
    registers: typing.List[str]
    modes: typing.List[ModeTemplate] = dataclasses.field(default_factory=list)
    # These are modes that can be used standalone and are converted to boolean keyword parameters
    modifiers: typing.List[ModeTemplate] = dataclasses.field(default_factory=list)

    ks_modes: typing.List[ModeTemplate] = dataclasses.field(default_factory=list)
    cs_modes: typing.List[ModeTemplate] = dataclasses.field(default_factory=list)
    uc_modes: typing.List[ModeTemplate] = dataclasses.field(default_factory=list)

    def all_mode_aliases(
        self, lib: typing.Literal["Ks", "Cs", "Uc"]
    ) -> typing.Set[str]:
        """
        Returns a list of literal values that can be used to select the mode. Omits modifiers since they are handleded differently
        This is used in the `Literal` type hint for the `mode` parameter of archist.core.Arch.Ks/Cs/Uc
        """

        def is_not_modifier(m: int | str) -> bool:
            return m not in [f"{mod.name.lower()}" for mod in self.modifiers]

        if lib == "Ks":
            modes = self.ks_modes
        elif lib == "Cs":
            modes = self.cs_modes
        elif lib == "Uc":
            modes = self.uc_modes
        else:
            raise ValueError(f"Not a valid value for lib: {lib}")

        collected_aliases: typing.Iterable[str | int] = filter(
            is_not_modifier, itertools.chain(*[m.aliases for m in modes])
        )
        return int_str_sorted(
            {
                f'"{alias}"' if type(alias) is str else alias
                for alias in collected_aliases
            }
        )


def generate_modes() -> typing.Dict[str, ModeTemplate]:
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

        aliases: typing.List[str | int] = [name.lower()]
        try:
            aliases.append(int(name))
        except ValueError:
            pass

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
            aliases=aliases,
        )
        modes.append(m)

    return {m.name: m for m in modes}


def generate_arches(modes: typing.Dict[str, ModeTemplate]) -> typing.List[ArchTemplate]:
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
        if name == "ALL":
            continue

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
            registers=generate_registers(name),
        )
        for mode in filter(lambda m: a.name in m.name, modes.values()):
            a.modes.append(mode)

        arches.append(a)
    arches.sort(key=lambda a: a.name)
    special_cases(arches, modes)

    # try all modes and only accept those that work
    for a in arches:
        for mode in a.modes:
            for lib, constructor in [
                ("keystone", "Ks"),
                ("capstone", "Cs"),
                ("unicorn", "Uc"),
            ]:
                mode_name = mode.name
                if mode.name.startswith("_"):
                    mode_name = mode.name[1:]

                # Some arches & modes are lacking different endianness support
                little = f"{lib}.{constructor}({lib}.{constructor.upper()}_ARCH_{a.name}, {lib}.{constructor.upper()}_MODE_{mode_name})"
                big = f"{little[:-1]} | {lib}.{constructor.upper()}_MODE_BIG_ENDIAN)"

                # TODO I rather dislike using eval here, but it validates which modes actually work on each arch
                little_valid = False
                big_valid = False
                try:
                    eval(little)
                    little_valid = True
                except Exception:
                    pass

                try:
                    eval(big)
                    big_valid = True
                except Exception:
                    pass

                # if a.name == "PPC" and lib=="unicorn":
                #     import IPython
                #     IPython.embed()
                if little_valid or big_valid:
                    # TODO encode endianless validity somewhere to update type hints
                    getattr(a, f"{constructor.lower()}_modes").append(mode)
    return arches


def special_cases(
    arches: typing.List[ArchTemplate], modes: typing.Dict[str, ModeTemplate]
) -> typing.List[ArchTemplate]:
    # Special Cases for:
    # - Modes that don't have the arch's name in thier const
    # - Modifier Modes that cant be used standalone
    # - Dealing with existing bugs or lack of support in capstone/keystone/unicorn

    for a in arches:
        name = a.name

        if name == "X86":
            a.modes += [modes["_16"], modes["_32"]]

        if name in ["X86", "PPC"]:
            a.modes.append(modes["_64"])

        if name == "ARM":
            a.modes += [modes["THUMB"], modes["MCLASS"], modes["V8"]]
            a.modifiers.append(modes["V8"])

        if name == "MIPS":
            a.modes.append(modes["MICRO"])
            a.modifiers += [
                modes["MICRO"],
                modes["MIPS2"],
                modes["MIPS3"],
                modes["MIPS32R6"],
            ]

        if name == "SPARC":
            a.modes.append(modes["V9"])
            a.modifiers.append(modes["V9"])

        if name == "PPC":
            # NOTE
            # modes["SPE"] and modes["BOOKE"] are omitted from this list because it is an invalid mode.
            # Appears to be another capstone bug or something that hasnt made its way to the latest release?
            a.modes += [modes["QPX"], modes["PS"]]

        if name == "MOS65XX":
            # NOTE
            # Claude says this being an invalid mode in capstone is a bug. Trying to use this will result in a CS_ERR_MODE
            a.modes.remove(modes["MOS65XX_65816"])

    return arches
