#!/bin/bash

# SLAE x86 Exam #1: Bind Shell
# 
# compile.sh: Update port if specified, then compile ${NAME}.nasm, 
# ${NAME}.c, and shellcode.c.
# 
# Author: Kerry Milan 
#         SLAE-1260
#         me@kerrymilan.com
#
# Usage: ./compile.sh [port] (optional)

ROOT=$(dirname $(readlink -f $0))
NAME="bindshell"

if [ ! -z $1 ]; then
    if [ $1 -lt 0  -o  $1 -gt 65535 ]; then
        echo "Invalid port specified: ${1}"
        exit 1
    fi

    PORT_INT=${1}
    PORT_HEX=$(printf "%04x0x" ${PORT_INT} | tac -rs .. | tr -d '\n')

    echo " [+] Updating port: ${PORT_INT} (${PORT_HEX})"
    sed -ri "s/^#define PORT [0-9]+\s*$/#define PORT ${PORT_INT}/" ${ROOT}/${NAME}.c
    sed -ri "s/0x[0-F]+\s+;\s*sin_port\s*$/${PORT_HEX}  ; sin_port/" ${ROOT}/${NAME}.nasm

    echo ${PORT_HEX:2:4} | egrep -q "(^00)|(00$)"
    [ $? -eq 0 ] && echo " [-] WARNING: This port introduces null chars into shellcode"
    
fi
    
echo -n " [+] Compiling ${NAME}.c..."
/usr/bin/gcc -ggdb3 -o ${ROOT}/${NAME}_c ${ROOT}/${NAME}.c > /dev/null 2>&1 
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

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
