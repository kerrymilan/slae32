#!/bin/bash

# SLAE x86 Exam #4: Encoder
# 
# compile.sh: compile ${NAME}.nasm, 
# ${NAME}.c, and shellcode.c.
# 
# Author: Kerry Milan 
#         SLAE-1260
#         me@kerrymilan.com

ROOT=$(dirname $(readlink -f $0))
NAME="swap-decoder-byte"

echo -n " [+] Compiling ${NAME}.nasm..."
/usr/bin/nasm -f elf32 ${ROOT}/${NAME}.nasm > /dev/null 2>&1 
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Linking ${NAME}.o..."
/usr/bin/ld ${ROOT}/${NAME}.o -o ${ROOT}/${NAME} > /dev/null 2>&1 
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Generating shellcode from ${NAME}..."
SHELLCODE=$(/usr/bin/objdump -D ${ROOT}/${NAME} \
            | egrep ":\s+([0-f]{2}\s)+" -o \
            | sed -r "s/^:\s+//g" \
            | sed -r "s/([0-f]{2})/\\\x\1/g" | tr -d "\n " \
            | fold -w 48 \
            | sed -r "s/(^.*$)/    \"\1\"/g"; \
            echo ";") 

[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Building shellcode.c..."
cat > ${ROOT}/shellcode.c << EOF
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
${SHELLCODE}

int main (int argc, char **argv) {
    printf("Shellcode Length:  %d\n", strlen(shellcode));
    int (*ret)() = (int(*)())shellcode;
    ret();
}
EOF
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Compiling shellcode.c..."
/usr/bin/gcc -ggdb3 -z execstack -fno-stack-protector \
    -o ${ROOT}/shellcode ${ROOT}/shellcode.c > /dev/null 2>&1 
[ $? -eq 0 ] && echo "Done" || echo "ERROR"
