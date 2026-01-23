# Preface
>  “By Zeus, must every ‘Aye’ and ‘Nay’ now demand its own sacred enumeration? Even the oracles grow weary of such redundancy.” — Gottfried Wilhelm Leibniz (allegedly, from beyond the grave, 1716)


```
> Doing VR
> Maybe need to assemble some shell code with Keystone
> or maybe disassemble a small asm snippet
> or maybe doing some dynamic analysis via emulation
> ???
> Why do all my imports look like copy pasta:
```

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from qiling.const import QL_ARCH, QL_OS

cs = Cs(CS_ARCH_X86, CS_MODE_32)
ks = Ks(KS_ARCH_X86, KS_MODE_32)
uc = Uc(UC_ARCH_X86, UC_MODE_32)
ql = Qiling(
        code=b"\x31\xc0\x40\x90",
        archtype=QL_ARCH.X86,
        ostype=QL_OS.LINUX,
        rootfs="/",
    )
```

Even better, they aren't consistent 🤮 🤢:
```python
>>> CS_ARCH_X86
3
>>> KS_ARCH_X86
4
>>> UC_ARCH_X86
4
>>> QL_ARCH.X86
<QL_ARCH.X86: 101>
```

All these enums that represent the same shit about each architecture. There should just be 1 interface for this.

# Archist

Archist is a convience library that maps all of these consts/enums together into a single intuitive class, such that you only need to import and use a single python object

The above example would become this with Archist

```python
from capstone import Cs, CS_MODE_32
from keystone import Ks, KS_MODE_32
from unicorn import Uc, UC_MODE_32
from qiling.const import QL_OS

from archist import X86

cs = Cs(X86.cs, CS_MODE_32)
ks = Ks(X86.ks, KS_MODE_32)
uc = Uc(X86.uc, UC_MODE_32)
ql = Qiling(
        code=b"\x31\xc0\x40\x90",
        archtype=X86.ql,
        ostype=QL_OS.LINUX,
        rootfs="/",
    )
```