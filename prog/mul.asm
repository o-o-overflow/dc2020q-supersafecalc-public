[BITS 64]

;loop:
;jmp loop
    
pop rbp
pop rbp
pop rcx
mov rax, rbp
mul rcx
push rax

add rsp, 0x10
mov rcx, 0x1001500 ; FUNCTIONS, epilogue
jmp rcx



