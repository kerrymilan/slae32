---
layout: post
title: "SLAE x86 Exam Part 3"
description: "SLAE x86 Exam Part 3: Egghunter"
modified: 2018-05-30T05:30:00-05:00
tags: [pentest, asm, x86, slae]
---

# Overview
This blog post has been created for completing the requirements of the
SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](/http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1260

---

In this portion of the exam, we explore the Egghunter shellcode.  This is a
method for locating pieces of shellcode within a program without knowing 
exactly where to look, useful when you need to break shellcode up into several
pieces and distribute it throughout the rest of the code.  I have derived the
majority of this writeup from Skape's seminal whitepaper[^1] on the subject,
titled "Safely Searching Process Virtual Address Space".  This paper is a
fantastically informative read, covering Egghunter at a conceptual level and
providing descriptions of several implementations on both Linux and Windows.  

## Egghunter concept

Generally, Egghunter works by traversing the entire memory space of a program
looking for a pre-defined "key", a sequence of several bytes that is (more or
less) guaranteed not to appear elsewhere in the code.  Once it finds its 
target, the program jumps to this location and continues with its execution.

There are several challenges associated with doing this, the most significant 
being that most programs don't handle attempts to access uninitialized memory 
space gracefully.  On Linux, there are only a handful of ways to do this while
keeping the shellcode small enough to be useful.  The 3 examples analyzed in 
the paper for doing so all query the kernel using system calls to find out if a
specific section of memory is valid and accessible without causing a
segmentation fault.  

## Egghunter implementation

I chose to focus on the second `access(2)` implementation in Skape's paper,
since it seemed to be the most time- and space-efficient while maintaining a
high level of robustness.  

Here is a pseudocode representation of this example:

{% highlight markdown %}

check_page(addr):
    align addr to start of next page
    check_addr(addr):
        call access(addr)
        EFAULT returned?
            goto check_page(addr)
        compare current and next DWORDs to egg
            jump to DWORD after egg if true
            otherwise, goto check_addr(addr+1)

{% endhighlight %}

This code makes highly effective use of the `scas` instruction[^2] when making
memory comparisons.  This approach has the additional benefit of automatically
incrementing (assuming the `DF` flag is set to `0`) the address stored in the
`EDI` register after each comparison.  

In this implementation, the key for which we are searching must appear twice in
succession to be considered 'found', to avoid triggering a false positive on the
declaration of the key itself.  There are other ways to do this, but none that
are as space-efficient.

Here is a proof-of-concept with both the egghunter code and the payload:

{% highlight nasm %}
global _start

section .text
_start:
    jmp egghunter       ; Go to Egghunter code

payload:
    xchg eax,ecx        ; Key, twice...
    xchg eax,edx
    xchg eax,edx
    xchg eax,ecx
    xchg eax,ecx
    xchg eax,edx
    xchg eax,edx
    xchg eax,ecx

    xor ebx, ebx        ; Begin "Hello world!" payload
    mul ebx             
    or al, 0x4
    inc ebx
    mov ecx, message
    mov dl, mlen
    int 0x80
    
    xor ebx, ebx        ; Exit 
    mul ebx
    inc eax
    int 0x80
    
egghunter:
    xor edx, edx        ; Register initialization

next_page:
    or dx, 0xfff        ; Align to next page

next_addr:
    inc edx             ; Increment addr in current page
    
    lea ebx, [edx+0x4]  ; ACCESS arg1: addr to check
    push byte 0x21      ; Load ACCESS syscall...
    pop eax             ; ...into EAX
    int 0x80            ; Exec interrupt

    cmp al, 0xf2        ; EFAULT returned?
    jz next_page        ; If so, skip to next page

    mov eax,0x91929291  ; Key
    mov edi,edx         ; Populate EDX for scasd
    scasd               ; Compare to key
    jnz next_addr       ; Jump if not matched
    scasd               ; Compare 2nd time
    jnz next_addr       ; Jump if not matched
    jmp edi             ; Jump to address after key
    
section .data:
    message: db "Hello world!", 0xA
    mlen equ $-message
{% endhighlight %}

Alternatively, here's a C wrapper:

{% highlight c %}
#include <stdio.h>
#include <string.h>

#define KEY "\x91\x92\x92\x91"

unsigned char egghunter[] = 
    "\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x8d\x5a"
    "\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8" KEY
    "\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

unsigned char payload[] = 
    KEY
    KEY
    "\x31\xdb\xf7\xe3\x43\x50\x0c\x04\x68\x61\x62\x63"
    "\x0a\x89\xe1\x88\xc2\xcd\x80\x89\xd8\xcd\x80";

int main(int argc, char **argv) {
    printf("Egghunter length: %d\n", strlen(egghunter));
    printf("Payload length: %d\n", strlen(payload));
    int (*ret)() = (int(*)())egghunter;
    ret();
}
{% endhighlight %}

I encountered some difficulty getting the C wrapper to work without segfaulting;
eventually, I discovered it was because I had a residual data in `ECX` going
into the `ACCESS` syscall.  Because of this, I was getting a return value of
`0xFFFFFFEA` (-22/`EINVAL`, according to 
`/usr/include/asm-generic/errno-base.h`); my egghunter was blowing through the 
jump after `cmp al,0xf2`, trying to look in address `0x1000` for the egg, and 
subsequently segfaulting.  Changing the `xor edx, edx` at the beginning to `xor 
ecx, ecx; mul ecx` did the trick.  

## Screenshots

![Execution of egghunter code]({{ "/assets/images/3.1-egghunter.png" | absolute_url}})

---

[^1]: http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf
[^2]: https://c9x.me/x86/html/file_module_x86_id_287.html
