#!/bin/bash

COMPILE () {
    echo -n " [+] Compiling and linking ${1}..."
    nasm ${1}.nasm -o ${1}.o -f elf32 && ld -o ${1} ${1}.o
    [ $? -eq 0 ] && echo "Done" || echo "ERROR"

    echo -n " [+] Extracting shellcode..."
    SHELLCODE=$(objdump -d ${1} \
        | egrep "^\s[^:]+:\s+([0-f]{2}\s)+" -o \
        | cut -f2- \
        | sed -r "s/([0-f]{2})/\\\ x\1/g" \
        | tr -d '\n ' \
        | fold -w48 \
        | sed -r "s/(.*)/\"\1\"/g")
    [ $? -eq 0 ] && echo "Done" || echo "ERROR"

    echo -n " [+] Building ${1}.c..."
    cat > ${1}.c << EOF
#include <stdio.h>
#include <string.h>

unsigned char code[] = 
${SHELLCODE};

int main (int argc, char **argv) {
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
EOF
    [ $? -eq 0 ] && echo "Done" || echo "ERROR"
    
    echo -n " [+] Compiling ${1}.c..."
    gcc -ggdb3 ${1}.c -o ${1}_c -fno-stack-protector -zexecstack
    [ $? -eq 0 ] && echo "Done" || echo "ERROR"
}

for i in {1..3}; do
    if [ -z ${1} ] || [ ${1} -eq ${i} ]; then
        COMPILE ${i}
    fi
done
