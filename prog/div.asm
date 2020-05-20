[BITS 64]

pop rbp
pop rbp
pop rcx
mov rax, rcx
div rbp; rdx:rax/rXX --> rax (rdx reminder) ; trigger SIGFPE if div by 0 OR integer overflow (possible if rdx is not 0 due to previous multiplications)
push rax

add rsp, 0x10
mov rcx, 0x1001500 ; FUNCTIONS, epilogue
jmp rcx

