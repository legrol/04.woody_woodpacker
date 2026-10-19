bits 32
section .text
global _start

_start:
    push dword 0
    pushfd
    pushad

    ; ptrace anti-debugging
    mov eax, 26
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    int 0x80
    test eax, eax
    js silent_exit

    ; get_vars_ptr
    call get_vars_ptr
get_vars_ptr:
    pop ebp
    add ebp, (vars - get_vars_ptr)

    ; printf woody
    mov eax, 4
    mov ebx, 1
    lea ecx, [ebp + (msg - vars)]
    mov edx, 14
    int 0x80

    ; mprotect
    mov esi, [ebp + 0]  ; rel_text
    add esi, ebp        ; esi = runtime _text

    mov ebx, esi
    and ebx, ~0xFFF     ; Page align (4KB)
    
    mov ecx, esi
    add ecx, [ebp + 4]  ; + text_size
    sub ecx, ebx        ; total size aligned
    
    mov eax, 125        ; sys_mprotect
    mov edx, 7          ; PROT_READ|PROT_WRITE|PROT_EXEC
    int 0x80


    mov ebx, [ebp + 4]   
    sub ebx, [ebp + 28]  
    add esi, ebx         
    ; RC4: Init S-Box
    sub esp, 256
    mov edi, esp
    
    xor ecx, ecx
init_sbox:
    mov [edi + ecx], cl
    inc ecx
    cmp ecx, 256
    jne init_sbox

    ; RC4: KSA
    xor ecx, ecx        ; i
    xor edx, edx        ; j
ksa_loop:
    movzx eax, byte [edi + ecx]
    add edx, eax
    
    mov eax, ecx
    and eax, 15         ; i % 16 (key is 16 bytes)
    lea ebx, [ebp + 8]  ; key starts at offset 8
    movzx eax, byte [ebx + eax]
    add edx, eax
    and edx, 0xFF

    mov al, [edi + ecx]
    mov bl, [edi + edx]
    mov [edi + ecx], bl
    mov [edi + edx], al

    inc ecx
    cmp ecx, 256
    jne ksa_loop

    ; RC4: PRGA
    xor ecx, ecx        ; i
    xor edx, edx        ; j
    xor ebx, ebx        ; total bytes counter

prga_loop:
    cmp ebx, [ebp + 28]
    je finish_rc4

    inc ecx
    and ecx, 0xFF
    
    movzx eax, byte [edi + ecx]
    add edx, eax
    and edx, 0xFF

    ; Swap S-Box[i] y S-Box[j]
    mov ah, [edi + ecx] ; Using ah instead of al so we keep i value free
    mov al, [edi + edx] ; ... ah wait, we're using al for S-Box[j]
    ; Let's just use bl...? No ebx is our counter.
    ; esi is text addr.
    ; ebp is vars.
    ; edi is S-box.
    ; ecx is i, edx is j.

    push ebx ; save counter temporarily for swap
    mov bl, [edi + ecx]
    mov bh, [edi + edx]
    mov [edi + ecx], bh
    mov [edi + edx], bl

    ; k = S-Box[j] + S-Box[i]
    add bl, bh
    movzx eax, bl
    mov al, [edi + eax]
    
    pop ebx ; restore counter

    ; XOR con texto
    xor byte [esi + ebx], al

    inc ebx
    jmp prga_loop

finish_rc4:
    add esp, 256


    ; ==========================================================================
    ; FASE 5.5: REHIDRATACIÓN 32-bits (LZSS)
    ; ==========================================================================
    mov ebx, [ebp + 4]
    sub ebx, [ebp + 28]
    mov edi, esi
    sub edi, ebx
    
    xor ebx, ebx
    xor edx, edx
    
.lzss_loop:
    cmp ebx, [ebp + 28]
    jge .lzss_done
    cmp edx, [ebp + 4]
    jge .lzss_done
    
    movzx eax, byte [esi + ebx]
    inc ebx
    push eax
    
    mov ecx, 1
    
.lzss_bit_loop:
    cmp ecx, 256
    jge .lzss_next_byte
    
    cmp ebx, [ebp + 28]
    jge .lzss_next_byte
    cmp edx, [ebp + 4]
    jge .lzss_next_byte
    
    mov eax, [esp]
    test eax, ecx
    jz .lzss_literal
    
    ; Reference
    mov eax, ebx
    inc eax
    cmp eax, [ebp + 28]
    jge .lzss_next_byte
    
    push ecx
    movzx eax, byte [esi + ebx]
    inc ebx
    movzx ecx, byte [esi + ebx]
    inc ebx
    shl ecx, 8
    or eax, ecx
    pop ecx
    
    push eax
    shr eax, 4
    and eax, 0xFFF
    mov [esp - 4], eax ; store offset
    
    push edi
    push esi
    
    mov esi, edx
    sub esi, eax
    
    mov eax, [esp + 8] ; pack
    and eax, 0xF
    add eax, 3 ; length
    
    push ecx
    xor ecx, ecx
.lzss_copy_loop:
    cmp ecx, eax
    jge .lzss_copy_done
    cmp edx, [ebp + 4]
    jge .lzss_copy_done
    
    push eax
    mov al, byte [edi + esi]
    mov byte [edi + edx], al
    pop eax
    
    inc esi
    inc edx
    inc ecx
    jmp .lzss_copy_loop
.lzss_copy_done:
    pop ecx
    pop esi
    pop edi
    pop eax
    jmp .lzss_bit_loop_next

.lzss_literal:
    movzx eax, byte [esi + ebx]
    inc ebx
    mov byte [edi + edx], al
    inc edx

.lzss_bit_loop_next:
    shl ecx, 1
    jmp .lzss_bit_loop

.lzss_next_byte:
    pop eax
    jmp .lzss_loop
    
.lzss_done:

    ; patch OEP
    mov edi, [ebp + 24] ; rel_oep (offset 24)
    add edi, ebp
    mov [esp + 36], edi

    popad
    popfd
    ret

silent_exit:
    mov eax, 1
    xor ebx, ebx
    int 0x80

align 8
vars:
    dq 0x1122334455667788 ; MUST match magic header for memmem!
    dq 0x0
    dq 0x0
    dq 0x0
    dq 0x0
    dq 0x0
    
msg:
    db "....WOODY....", 10
