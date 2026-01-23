#!/usr/bin/env python3
"""Generate source files from Jinja templates."""

from pathlib import Path
import re
import itertools

import capstone
import keystone
import unicorn
import qiling.const
from jinja2 import Environment, FileSystemLoader

CODEGEN_DIR = Path(__file__).parent
TEMPLATES_DIR = CODEGEN_DIR / "templates"
SRC_DIR = CODEGEN_DIR.parent / "src" / "archist"

# Libraries that use a <int> type const as a fake enum
INT_CONSTS_LIBS = [capstone, keystone, unicorn]

def getattr_regex(obj, pattern):
    return {name: getattr(obj, name) for name in dir(obj) if re.match(pattern, name)}

def non_dunder_members(obj):
    return {name: getattr(obj, name) for name in dir(obj) if not name.startswith("__") and not name.endswith("__")}

def generate_arches():
    # Group 1 => Library prefix (UC == Unicorn)
    # Group 2 => Arch name
    var_pattern = re.compile(r"(\w\w)_ARCH_(\w+)")
    all_consts = itertools.chain(*[getattr_regex(lib, var_pattern) for lib in INT_CONSTS_LIBS])
    
    # Union of all arches supported by all 4 libaries
    arch_names = set([var.rsplit("_", 1)[1] for var in all_consts] + \
                 list(non_dunder_members(qiling.const.QL_ARCH).keys()))

    arches = list()
    for name in arch_names:
        a = dict()
        a['name'] = name
        a['ks'] = f"keystone.KS_ARCH_{name}" if hasattr(keystone, f"KS_ARCH_{name}") else "-1"
        a['cs'] = f"capstone.CS_ARCH_{name}" if hasattr(capstone, f"CS_ARCH_{name}") else "-1"
        a['uc'] = f"unicorn.UC_ARCH_{name}" if hasattr(unicorn, f"UC_ARCH_{name}") else "-1"
        a['ql'] = f"qiling.const.QL_ARCH.{name}" if hasattr(qiling.const.QL_ARCH, name) else "None"
        arches.append(a)
    arches.sort(key = lambda x: x["name"])

    # Create python file
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

    template = env.get_template("arches.py.jinja")
    output = template.render(arches=arches)

    output_path = SRC_DIR / "__init__.py"
    output_path.write_text(output)
    print(f"Generated {output_path}")

def main() -> None:
    generate_arches()


if __name__ == "__main__":
    main()
