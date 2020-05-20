[BITS 64]

pop rdx
pop rdx
pop rcx
sub rcx, rdx
push rcx

add rsp, 0x10
mov rcx, 0x1001500 ; FUNCTIONS, epilogue
jmp rcx

