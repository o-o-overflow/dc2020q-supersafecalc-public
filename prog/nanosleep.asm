[BITS 64]

mov rax, 35
push 0
push 15
mov rdi, rsp
mov rsi, 0
syscall
_loop:
jmp _loop



