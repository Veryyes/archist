#!/bin/bash
set -euo pipefail

OUT=/build/out
mkdir -p "$OUT"

cat > /build/main.c << 'EOF'
void _start(void) { for(;;); }
EOF

# ARM LE (ARM mode)
arm-linux-gnueabi-gcc -static -nostartfiles -o "$OUT/arm_le.elf" /build/main.c

# ARM Thumb LE
arm-linux-gnueabi-gcc -static -nostartfiles -mthumb -o "$OUT/arm_thumb_le.elf" /build/main.c

# AArch64 LE
aarch64-linux-gnu-gcc -static -nostartfiles -o "$OUT/aarch64_le.elf" /build/main.c

# MIPS32 BE
mips-linux-gnu-gcc -static -nostartfiles -o "$OUT/mips32_be.elf" /build/main.c

# MIPS32 LE
mipsel-linux-gnu-gcc -static -nostartfiles -o "$OUT/mips32_le.elf" /build/main.c

# MIPS64 BE
mips64-linux-gnuabi64-gcc -static -nostartfiles -o "$OUT/mips64_be.elf" /build/main.c

# PPC32 BE
powerpc-linux-gnu-gcc -static -nostartfiles -o "$OUT/ppc32_be.elf" /build/main.c

# PPC64 BE
powerpc64-linux-gnu-gcc -static -nostartfiles -o "$OUT/ppc64_be.elf" /build/main.c

# SPARC64 BE
sparc64-linux-gnu-gcc -static -nostartfiles -o "$OUT/sparc64_be.elf" /build/main.c

# RISC-V 64 LE
riscv64-linux-gnu-gcc -static -nostartfiles -o "$OUT/riscv64_le.elf" /build/main.c

# M68K BE
m68k-linux-gnu-gcc -static -nostartfiles -o "$OUT/m68k_be.elf" /build/main.c

# SH4 LE
sh4-linux-gnu-gcc -static -nostartfiles -o "$OUT/sh4_le.elf" /build/main.c

# S390x BE
s390x-linux-gnu-gcc -static -nostartfiles -o "$OUT/s390x_be.elf" /build/main.c

# x86 32-bit LE
i686-linux-gnu-gcc -static -nostartfiles -o "$OUT/x86_32_le.elf" /build/main.c

# x86-64 LE (native)
gcc -static -nostartfiles -o "$OUT/x86_64_le.elf" /build/main.c

echo "Built $(ls "$OUT"/*.elf | wc -l) ELF binaries"
