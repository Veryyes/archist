import enum
import typing

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

        found = getattr(cls.Modes, mode, None)
        if found is not None:
            return found
        raise NotImplementedError(
            f"No such mode ({mode}) exists for architecture: {cls.__name__}"
        )

    @classmethod
    def Ks(cls, mode: Mode | typing.Any = NO_MODES):
        if cls.ks is None:
            raise NotImplementedError(f"No Keystone Implementation of: {cls.__name__}")
        return keystone.Ks(cls.ks, cls._mode_lookup(mode).ks)

    @classmethod
    def Cs(cls, mode: Mode | typing.Any = NO_MODES):
        if cls.cs is None:
            raise NotImplementedError(f"No Capstone Implementation of: {cls.__name__}")
        return capstone.Cs(cls.cs, cls._mode_lookup(mode).cs)

    @classmethod
    def Uc(cls, mode: Mode | typing.Any = NO_MODES):
        if cls.uc is None:
            raise NotImplementedError(f"No Unicorn Implementation of: {cls.__name__}")
        return unicorn.Uc(cls.uc, cls._mode_lookup(mode).uc)

    @classmethod
    def modes(cls) -> typing.List[Mode]:
        if hasattr(cls, "mode"):
            return [
                m for m_name, m in vars(cls.mode).items() if not m_name.startswith("_")
            ]
        return list()

    def __hash__(self) -> int:
        return hash(self.name)
