global _start

section .text
_start:
    xor ebx, ebx        ; Begin "Hello world!" payload
    mul ebx
    inc ebx
    push eax
    or al, 0x4
    push 0x0A646c72
    push 0x6f77206f
    push 0x6c6c6548
    mov ecx, esp
    mov dl, 0xc
    int 0x80
    
    mov eax, ebx
    int 0x80

