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


class Arch(Common):
    ql: qiling.const.QL_ARCH | None
    mode: typing.Dict[str, Mode] = {}

    @property
    def modes(self):
        return list(self.mode.keys())
