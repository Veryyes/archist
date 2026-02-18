import pathlib
import shutil
import subprocess

import pytest

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures" / "elfs"

EXPECTED_ELFS = [
    "arm_le.elf",
    "arm_thumb_le.elf",
    "aarch64_le.elf",
    "mips32_be.elf",
    "mips32_le.elf",
    "mips64_be.elf",
    "ppc32_be.elf",
    "ppc64_be.elf",
    "sparc64_be.elf",
    "riscv64_le.elf",
    "m68k_be.elf",
    "sh4_le.elf",
    "s390x_be.elf",
    "x86_32_le.elf",
    "x86_64_le.elf",
]

IMAGE_NAME = "archist-cross-compile"


def _elfs_present() -> bool:
    return all((FIXTURES_DIR / name).exists() for name in EXPECTED_ELFS)


@pytest.fixture(scope="session")
def elf_fixtures() -> pathlib.Path:
    """Build cross-compiled ELF binaries via Docker if not already present."""
    if _elfs_present():
        return FIXTURES_DIR

    if not shutil.which("docker"):
        pytest.skip("Docker not available and ELF fixtures not pre-built")

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    tests_dir = pathlib.Path(__file__).parent

    # Build Docker image
    subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, "-f", "Dockerfile.cross-compile", "."],
        cwd=tests_dir,
        check=True,
    )

    # Extract binaries via a temporary container
    result = subprocess.run(
        ["docker", "create", IMAGE_NAME],
        capture_output=True,
        text=True,
        check=True,
    )
    container_id = result.stdout.strip()

    try:
        subprocess.run(
            ["docker", "cp", f"{container_id}:/build/out/.", str(FIXTURES_DIR)],
            check=True,
        )
    finally:
        subprocess.run(["docker", "rm", container_id], check=True)

    missing = [name for name in EXPECTED_ELFS if not (FIXTURES_DIR / name).exists()]
    if missing:
        raise RuntimeError(f"Docker build did not produce expected ELFs: {missing}")

    return FIXTURES_DIR
