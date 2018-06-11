#!/bin/bash

# Look at single payloads in /linux/x86/:
ARCH="linux/x86"
PAYLOADS=$(find /usr/share/metasploit-framework/modules/payloads/singles/${ARCH} -type f \
    | rev | cut -d/ -f1 | rev | cut -d. -f1 | sort)

# Generate 3:
for x in {1..3}; do
    # Get payload count
    P_LEN=$(echo "${PAYLOADS}" | wc -l)

    # Select a random payload index
    P_IDX=$((1 + RANDOM % ${P_LEN}))

    # Get the name of the payload at that index
    PAYLOAD=$(echo "${PAYLOADS}" | head -n ${P_IDX} | tail -n1)

    # Print header
    echo -e "global _start\n\nsection .text\n_start:" > ${x}.nasm

    # Generate the selected payload. Use dummy data for any fields likely to 
    # be required. Then, strip out instructions, build, and link
    msfvenom -p ${ARCH}/${PAYLOAD} \
        PATH=/etc/hostname \
        RHOST=127.1.1.1 \
        RPORT=4444 \
        LHOST=127.1.1.1 \
        LPORT=4444 \
        CMD=id \
        | ndisasm -b32 - > ${x}.asm
    sed -r 's/^[0-F]+\s+[0-F]+\s+/    /g' ${x}.asm >> ${x}.nasm
    nasm ${x}.nasm -f elf32 -o ${x}.o
    ld -m elf_i386 -o ${x} ${x}.o

    # Insert shellcode into .c template and compile
    SHELLCODE=$(cat ./${x}.asm | awk '{print $2}' | tr -d '\n' | sed -r 's/(..)/\\x\1/g')
    cat > ${x}.c << EOF
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "${SHELLCODE}";

int main(int argc, char **argv) {
    int (*ret)() = (int(*)())shellcode;

    ret();
}
EOF
    gcc -ggdb3 ${x}.c -o ${x} -fno-stack-protector -z execstack
done
