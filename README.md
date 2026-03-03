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

If I want to do stuff with Capstone, Keystone and/or Unicorn it can be rather verbose:
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

Though constant values are not expected to be consistent across different libraries, these are all written by the same author and hold the same style of code. So, you may want to believe consts would have some sort of consistency across each library:
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

All these enums that represent the information about each architecture. There should just be a single interface for this.

# Archist

Archist is a convenience library that maps all of these consts/enums together into a single intuitive class per architecture, such that you only need to import and use a single python object. Since a large part of the code base is generated and statically defines relationships between architectures and their properties, IDEs can autocomplete and static type checkers actually understand parts of the code base. Qiling, for example, dynamically maps in values (e.g. `ql.arch.Regs.eax`), so most static type checkers would reason the type of that value to be `typing.Any`. 

I also personally find it annoying to import and use a crap ton of constant values like C-style preprocessor `#define`s when writing python code.

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
You're likely also using other libraries when doing some binary analysis. Pass in the "main" top level object used to represent your binary or program into `Ks`/`Cs`/`Uc` of the respective module you want to use. Additionally, for unicorn, these helpers do **NOT** load the binary into unicorn's emulated memory, it just spits out a `Uc` object configured for that architecture, endianness and modes if applicable.

### [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
Pass in the `Program` object (from `pyghidra.program_context()`) into the helper functions
```python
import tempfile
import pyghidra
from archist.extensions.ghidra import Ks, Cs, Uc

pyghidra.start()
tmpdir = tempfile.mkdtemp()
with pyghidra.open_project(tmpdir, "example_proj", create=True) as project:
    loader = pyghidra.program_loader().project(project).source("/bin/ls")
    with loader.load() as load_results:
        load_results.save(pyghidra.task_monitor())
        
    with pyghidra.program_context(project, "/ls") as program:
        ks = Ks(program)
        cs = Cs(program)
        uc = Uc(program)
```

### [Binary Ninja](https://binary.ninja/)
Requires you have the Binary Ninja (duh). Pass in `binaryninja.BinaryView` to the helper functions
```python
import binaryninja as bn
from archist.extensions.binja import Ks, Cs, Uc

with bn.load("/bin/ls") as bv:
    ks = Ks(bv)
    cs = Cs(bv)
    uc = Uc(bv)
```

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
pwntools' `pwn.elf.ELF` object is just a subclass of pyelftools' `elftools.elf.elffile.ELFFile`, so just use the functions above.

**NOTE:** As of writing this, the latest version of pwntools explicitly excludes the unicorn versions 2.1.3 and 2.1.4 because of an [issue](https://github.com/unicorn-engine/unicorn/issues/2134) with MIPS emulation. 2.1.4 is the latest version of unicorn and Archist its generated against that. Using an older version of unicorn with archist may result in some incompatibilities.

### [LIEF](https://github.com/lief-project/LIEF)
Pretty similar setup to pyelftools
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
- Test support for not ELF files and implement if needed
- Parse .slaspec files Ghidra
- Add compatibiltiy with angr/archinfo
- Reverse lookup (i.e. capstone.CS_ARCH_ARM -> archist.ARM)