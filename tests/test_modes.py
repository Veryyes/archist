"""Test accessing all modes in a given arch."""

from archist import ARM
from archist.modes import ARM1176, ARM926, ARM946, ARMBE8, THUMB, MCLASS, V8
from archist.modes import ARM as ARM_mode


def test_modes() -> None:
    expected = {ARM_mode, ARM1176, ARM926, ARM946, ARMBE8, THUMB, MCLASS, V8}
    assert len(expected.symmetric_difference(set(ARM.modes()))) == 0
