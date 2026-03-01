"""Registers generation logic"""

import re
import typing
import logging
import importlib
import importlib.util

from utils import getattr_regex

logger = logging.getLogger(__file__)


def _skip_numeric_regs(regs: typing.Dict[str, str]) -> typing.Dict[str, str]:
    renamed_regs: typing.Dict[str, str] = dict()
    for name, value in regs.items():
        try:
            int(name)
            continue
        except ValueError:
            renamed_regs[name] = value
    return renamed_regs


def _rename_ppc_regs(regs: typing.Dict[str, str]) -> typing.Dict[str, str]:
    renamed_regs: typing.Dict[str, str] = dict()
    for name, value in regs.items():
        try:
            int(name)
            renamed_regs[f"R{name}"] = value
        except ValueError:
            renamed_regs[name] = value
    return renamed_regs


def generate_registers(arch: str) -> typing.Dict[str, str]:
    module_name = f"unicorn.{arch.lower()}_const"
    spec = importlib.util.find_spec(module_name)
    if spec is None:
        logger.warning(f"Not a module in unicorn. Skipping: {module_name}")
        return dict()

    var_pattern = re.compile(rf"UC_{arch.upper()}_REG_(\w+)")
    mod = importlib.import_module(module_name)
    regs = getattr_regex(mod, var_pattern, group_no=1)
    # Because we dont actually care what the enum value is and we have to rename registers for PPC,
    # Update regs to be a mapping of archist_var_name -> variable name from library
    regs = {
        name: f"{module_name}.UC_{arch}_REG_{name}" for name in regs.keys()
    }  # ugh i hate this line

    # Special case for MIPS and PCC
    # These arches use numbers as their register names (which is retarded) and can't be used as python variable names
    if arch.lower() == "mips":
        # For MIPS:
        #   register "2" is colloquially known as v0, and already has aliasing for these in their enums,
        #   so we skip the number only registers
        regs = _skip_numeric_regs(regs)

    elif arch.lower() == "ppc":
        # For PPC:
        #   register "3" is usually refered to as r3 or GPR3 in reverse engineer context and in thew newer IBM docs
        #   (they used to be numbers only because of some really old [retarded] historical reason)
        #   so we will prefix all numbered registers with "r" because that what most people are used to.
        #   e.g. 3 -> r3
        regs = _rename_ppc_regs(regs)

    return regs
