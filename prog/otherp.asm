[BITS 64]



mov rax, 35
mov rdi, 0x1002fd0; STACKEND
mov rsi, 0
sleep:
mov rax, 35
syscall ; nanosleep 1 sec
mov rcx, qword [0x1002ff0]; STACKEND
test rcx, rcx
je sleep

; deallocate everything we do not need
mov rax, 11
mov rdi, 0x0;
mov rsi, 0x1000000; OTHERP
syscall ; munmap lower

mov rax, 11
mov rdi, 0x1003000 ; STACKEND
mov rsi, 0x7ffffeffc000; 0x7ffffffff000 - STACKEND
syscall ; munmap upper

mov rdi, 4; the writing side of the pipe
mov rsi, 0x1001000 ; CODE
mov rdx, 0x2000 ; 
finalsyscallloop: ; this should not be useful
mov rax, 1
syscall ; write 8K to a 4K pipe will block us
; the other thread can know when we are done checking the size of the content of the pipe
jmp finalsyscallloop
