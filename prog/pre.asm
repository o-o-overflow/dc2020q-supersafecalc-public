[BITS 64]
mov qword [0x1002ff0], 1; STACKEND; we started --> the other thread can delete all normal stub memory

checkpipesize:
mov rax, 16
mov rdi, 4
mov rsi, 0x541B ;FIONREAD
mov rdx, 0x1002ff8; STACKEND
syscall ; we check the size of the pipe to be sure that the other thread is done

mov rax, 35
mov rdi, 0x1002fd0; STACKEND
mov rsi, 0
syscall ; nanosleep 1 sec

mov rax, qword [0x1002ff8]; STACKEND
cmp rax, 0x1000; 0x1000-1
jl checkpipesize

mov rax, 35
mov rdi, 0x1002fd0; STACKEND
mov rsi, 0
syscall ; nanosleep 1 sec, it may not be necessary

mov rax, 11
mov rdi, 0x1000000; OTHERP
mov rsi, 0x1000
syscall ; this makes gdb going crazy since it creates a thread that is stuck and without memory

xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
xor rsi, rsi
xor rdi, rdi
xor rbp, rbp
mov rsp, 0x1002200; STACKBOTTOM
mov rcx, 0x1001700; GCODE

jmp rcx

