#!/bin/bash

# TODO: Automatically replace key in egghunter-code.nasm
KEY="\\\x91\\\x92\\\x92\\\x91"

echo -n " [+] Compiling and linking egghunter-code.nasm..."
nasm egghunter-code.nasm -o egghunter-code.o -f elf32 && \
ld -o egghunter-code egghunter-code.o
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Compiling and linking egghunter-payload.nasm..."
nasm egghunter-payload.nasm -o egghunter-payload.o -f elf32 && \
ld -o egghunter-payload egghunter-payload.o
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Extracting shellcode..."
# Note: Removing 48-char line breaks to allow for consistent KEY substitution
CODE=$(objdump -d egghunter-code | egrep "^\s[^:]+:\s+([0-f]{2}\s)+" -o | cut -f2- | sed -r "s/([0-f]{2})/\\\x\1/g" | tr -d '\n ' | sed -r "s/${KEY}/\" KEY \"/" | sed -r "s/(.*)/\"\1\"/g") #fold -w48 | 
PAYLOAD=$(objdump -d egghunter-payload | egrep "^\s[^:]+:\s+([0-f]{2}\s)+" -o | cut -f2- | sed -r "s/([0-f]{2})/\\\x\1/g" | tr -d '\n ' | fold -w48 | sed -r "s/(.*)/\"\1\"/g")
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Building egghunter.c..."
# Note: $(echo -ne "${KEY}") ensures unescaped output; "${KEY}" does not
cat > egghunter.c << EOF
#include <stdio.h>
#include <string.h>

#define KEY "$(echo -ne "${KEY}")"

unsigned char egghunter[] = 
${CODE};

unsigned char payload[] = 
KEY
KEY
${PAYLOAD};

int main(int argc, char **argv) {
    printf("Egghunter length: %d\n", strlen(egghunter));
    printf("Payload length: %d\n", strlen(payload));
    int (*ret)() = (int(*)())egghunter;
    ret();
}
EOF
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Compiling egghunter.c..."
gcc -ggdb3 egghunter.c -o egghunter -fno-stack-protector -zexecstack
[ $? -eq 0 ] && echo "Done" || echo "ERROR"

echo -n " [+] Cleaning up..."
rm egghunter-code.o egghunter-code egghunter-payload.o egghunter-payload
[ $? -eq 0 ] && echo "Done" || echo "ERROR"
