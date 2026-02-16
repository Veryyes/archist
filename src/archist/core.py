import enum
import typing
import functools
import operator

import pydantic
import keystone
import capstone
import unicorn
import qiling.const


class Common(pydantic.BaseModel):
    name: str
    ks: int | None
    cs: int | None
    uc: int | None
    ql: enum.IntEnum | None


class Endian(Common):
    ql: qiling.const.QL_ENDIAN | None


##########
# ENDIAN #
##########
# All the consts for little endian are the same (but not big endian)
BIG_ENDIAN = Endian(
    name="big",
    ks=keystone.KS_MODE_BIG_ENDIAN,
    cs=capstone.CS_MODE_BIG_ENDIAN,
    uc=unicorn.UC_MODE_BIG_ENDIAN,
    ql=qiling.const.QL_ENDIAN.EB,
)

# Little Endian happens to be the same const across all of these libs
assert (
    capstone.CS_MODE_LITTLE_ENDIAN
    == keystone.KS_MODE_LITTLE_ENDIAN
    == unicorn.UC_MODE_LITTLE_ENDIAN
)
LITTLE_ENDIAN = Endian(
    name="little",
    ks=keystone.KS_MODE_LITTLE_ENDIAN,
    cs=keystone.KS_MODE_LITTLE_ENDIAN,
    uc=keystone.KS_MODE_LITTLE_ENDIAN,
    ql=qiling.const.QL_ENDIAN.EL,
)


class Mode(pydantic.BaseModel):
    name: str
    ks: int | None
    cs: int | None
    uc: int | None

    def __hash__(self) -> int:
        return hash(self.name)


NO_MODES = Mode(name="N/A", ks=0, cs=0, uc=0)


class Arch(pydantic.BaseModel):
    name: typing.ClassVar[str]
    ks: typing.ClassVar[int | None]
    cs: typing.ClassVar[int | None]
    uc: typing.ClassVar[int | None]
    ql: typing.ClassVar[enum.IntEnum | None]

    class Modes:
        pass

    @classmethod
    def _mode_lookup(cls, mode: Mode | typing.Any) -> Mode:
        """Does a getattr based lookup in the Mode subclass of Arch"""
        if isinstance(mode, Mode):
            return mode

        # Handles Numbers or numbers encoded as a string
        if isinstance(mode, int) or (isinstance(mode, str) and mode.isdigit()):
            mode = f"_{mode}"

        assert isinstance(mode, str)
        mode = mode.lower()

        found = getattr(cls.Modes, mode, None)
        if found is not None:
            return found
        raise NotImplementedError(
            f"No such mode ({mode}) exists for architecture: {cls.__name__}"
        )

    @classmethod
    def _endian_lookup(cls, endian: Endian | str) -> Endian:
        if isinstance(endian, Endian):
            return endian
        if endian.lower() == "little":
            return LITTLE_ENDIAN
        elif endian.lower() == "big":
            return BIG_ENDIAN
        else:
            # No Middle Endian here lol
            raise ValueError(f"Unidentifiable Endianness: {endian}")

    @classmethod
    def _Ks(
        cls,
        endian: Endian | str = LITTLE_ENDIAN,
        mode: Mode | typing.Any = NO_MODES,
        **kwargs,
    ):
        if cls.ks is None:
            raise NotImplementedError(f"No Keystone Implementation of: {cls.__name__}")
        return keystone.Ks(
            cls.ks,
            functools.reduce(
                operator.or_,
                [cls._mode_lookup(mode).ks, cls._endian_lookup(endian).ks]
                + [
                    cls._mode_lookup(variant).ks
                    for variant, enabled in kwargs.items()
                    if enabled
                ],
            ),
        )

    @classmethod
    def _Cs(
        cls,
        endian: Endian | str = LITTLE_ENDIAN,
        mode: Mode | typing.Any = NO_MODES,
        **kwargs,
    ):
        if cls.cs is None:
            raise NotImplementedError(f"No Capstone Implementation of: {cls.__name__}")
        return capstone.Cs(
            cls.cs,
            functools.reduce(
                operator.or_,
                [cls._mode_lookup(mode).cs, cls._endian_lookup(endian).cs]
                + [
                    cls._mode_lookup(variant).cs
                    for variant, enabled in kwargs.items()
                    if enabled
                ],
            ),
        )

    @classmethod
    def _Uc(
        cls,
        endian: Endian | str = LITTLE_ENDIAN,
        mode: Mode | typing.Any = NO_MODES,
        **kwargs,
    ):
        if cls.uc is None:
            raise NotImplementedError(f"No Unicorn Implementation of: {cls.__name__}")
        return unicorn.Uc(
            cls.uc,
            functools.reduce(
                operator.or_,
                [cls._mode_lookup(mode).uc, cls._endian_lookup(endian).uc]
                + [
                    cls._mode_lookup(variant).uc
                    for variant, enabled in kwargs.items()
                    if enabled
                ],
            ),
        )

    @classmethod
    def modes(cls) -> typing.List[Mode]:
        return [
            m for m_name, m in vars(cls.Modes).items() if not m_name.startswith("_")
        ]

    def __hash__(self) -> int:
        return hash(self.name)
