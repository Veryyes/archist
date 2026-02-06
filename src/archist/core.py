import enum
import typing

import pydantic
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


class Arch(pydantic.BaseModel):
    name: typing.ClassVar[str]
    ks: typing.ClassVar[int | None]
    cs: typing.ClassVar[int | None]
    uc: typing.ClassVar[int | None]
    ql: typing.ClassVar[enum.IntEnum | None]

    @classmethod
    def modes(cls) -> typing.List[Mode]:
        if hasattr(cls, "mode"):
            return [
                m for m_name, m in vars(cls.mode).items() if not m_name.startswith("_")
            ]
        return list()

    def __hash__(self) -> int:
        return hash(self.name)
