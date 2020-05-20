[BITS 64]

mov rax, rsp
sub rsp, 0x10
mov rcx, qword [rax-0x20]
jmp rcx


