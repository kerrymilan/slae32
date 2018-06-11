#!/bin/bash

ASM=$1

[ ! -z ${ASM} ] || { echo "No file specified"; exit 1; }

ELF="${ASM::-5}"
OUT=${ELF}.o

rm ${ELF} ${OUT} ${ELF}.c ${ELF}_c 2>/dev/null

nasm -f elf32 -o ${OUT} ${ASM} || echo "Compile failed"
ld -o ${ELF} ${OUT} || echo "Link failed"

SRC=$(objdump -d ${ELF} \
    | egrep "^\s[^:]+:\s+([0-f]{2}\s)+" -o \
    | cut -f2- \
    | sed -r "s/([0-f]{2})/\\\x\1/g" \
    | tr -d '\n ' \
    | fold -w48 \
    | sed -r "s/(.*)/\"\1\"/g")

cat > ${ELF}.c << EOF
#include <string.h>
#include <stdio.h>

unsigned char code[] = 
${SRC};

int main (int argc, char **argv) {
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
EOF

gcc -ggdb3 ${ELF}.c -o ${ELF}_c -fno-stack-protector -zexecstack || echo "GCC failed"
