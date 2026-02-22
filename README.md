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
# Example Code snippet
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_BIG_ENDIAN
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN)
ks = Ks(KS_ARCH_X86, KS_MODE_32)
uc = Uc(UC_ARCH_X86, UC_MODE_32)
ql = Qiling(
        code=b"\x31\xc0\x40\x90",
        archtype=QL_ARCH.X86,
        ostype=QL_OS.LINUX,
        rootfs="/",
    )

uc.reg_write(UC_X86_REG_EAX, 0xdeadbeef)
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

Archist is a convenience library that maps all of these consts/enums together into a single intuitive class per architecture, such that you only need to import and use a single python object. Since a large part of the code base is generated and statically defines relationships between architectures and their properties, IDEs can autocomplete and static type checkers actually understand parts of the code base. Qiling, for example, dynamically maps in values (e.g. `ql.arch.regs.eax`), so most static type checkers would reason the type of that value to be `typing.Any`. I also personally find it annoying to import and use a crap ton of constant values like C-style preprocessor `#define`s when writing python code.

The above example would become this with Archist:

```python
from qiling import Qiling
from qiling.const import QL_OS

from archist import X86

cs = ARM.Cs(mode="thumb", endian="big")
ks = X86.Ks(mode=32)
uc = X86.Uc(mode="32") # String is valid too
ql = Qiling(
        code=b"\x31\xc0\x40\x90",
        archtype=X86.ql,
        ostype=QL_OS.LINUX,
        rootfs="/",
    )

uc.reg_write(X86.Regs.eax, 0xdeadbeef)
```

## Compatibility with other Tools/Libraries
You're likely also using other libraries when doing some binary analysis

### [pyelftools](https://github.com/eliben/pyelftools)
Pass in the `ELFFile` to these helper functions
```python
from elftools.elf.elffile import ELFFile
from archist.extensions.pyelftools import Ks, Cs, Uc

with open("/bin/ls", 'rb') as f:
    elf = ELFFile(f)

    ks = Ks(elf)
    cs = Cs(elf)
    uc = Uc(elf)
```

### [pwntools](https://github.com/Gallopsled/pwntools)
pwntools' `pwn.elf.ELF` object is just a subclass of pyelftools' `elf.tools.elf.elffile.ELFFile`, so just use the `*_pyelftools(elf)` functions above.

**NOTE:** As of writing this, the latest version of pwntools explicitly excludes the unicorn versions 2.1.3 and 2.1.4 because of an [issue](https://github.com/unicorn-engine/unicorn/issues/2134) with MIPS emulation. 2.1.4 is the latest version of unicorn and Archist its generated against that. Using an older version of unicorn with archist may result in some incompatibilities.

### [LIEF](https://github.com/lief-project/LIEF)
```python
import lief
from archist.extensions.lief import Ks, Cs, Uc

elf = lief.ELF.parse("/bin/ls")

ks = Ks(elf)
cs = Cs(elf)
uc = Uc(elf)
```

## Future Plans
- Better Qilling support
- Parse .slaspec files Ghidra
- Create a class to represent Ghidra's language triples (Processor:Endianness:Bits:Compiler/Varient)
- auto create keystone, capstone, unicorn or (partially) qiling objects using Ghidra language triples
- Add compatibiltiy with angr/archinfo
- Reverse lookup (i.e. capstone.CS_ARCH_ARM -> archist.ARM)