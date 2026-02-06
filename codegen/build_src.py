#!/usr/bin/env python3
"""Generate source files from Jinja templates."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from arches import generate_modes, generate_arches

CODEGEN_DIR = Path(__file__).parent
TEMPLATES_DIR = CODEGEN_DIR / "templates"
SRC_DIR = CODEGEN_DIR.parent / "src" / "archist"


def output_template(template_file: str, output_file: str, **template_values):
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template(template_file)
    output = template.render(**template_values)

    output_path = SRC_DIR / output_file
    output_path.write_text(output)
    print(f"Generated {output_path}")
    return output


def main() -> None:
    modes = generate_modes()
    output_template("modes.py.jinja", "modes.py", modes=modes)

    arches = generate_arches(modes)
    output_template("arches.py.jinja", "__init__.py", arches=arches, modes=modes)


if __name__ == "__main__":
    main()
