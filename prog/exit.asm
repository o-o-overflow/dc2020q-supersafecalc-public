[BITS 64]

mov rdx, 0x1ff
mov rsi, 0x241
mov rdi, 0x1002fe0; STACKEND 
mov rax, 2
syscall ; open

mov rbp, rax

mov rdi, rax
mov rsi, rsp
mov rdx, 8
mov rax, 1
syscall ; write

mov rdi, rbp
mov rax, 3
syscall ; close

mov rax, 231
mov rdi, 7
syscall ; exit_group

