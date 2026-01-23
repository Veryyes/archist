import pydantic
import qiling.const


class Arch(pydantic.BaseModel):
    name: str
    ks: int
    cs: int
    uc: int
    ql: qiling.const.QL_ARCH | None
