
#define _GNU_SOURCE
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "asm.h"

unsigned char*  OTHERP      = (unsigned char*)0x1000000;
unsigned char*  CODE        = (unsigned char*)0x1001000;
unsigned char*  FUNCTIONS   = (unsigned char*)0x1001100;
unsigned char*  EXITF       = (unsigned char*)0x1001600;
unsigned char*  GCODE       = (unsigned char*)0x1001700;
unsigned char*  STACK       = (unsigned char*)0x1002000;
unsigned char*  STACKBOTTOM = (unsigned char*)0x1002200;
unsigned char*  VARS        = (unsigned char*)0x1002f00;
unsigned char*  STACKEND    = (unsigned char*)0x1003000;


unsigned char hex2bin(unsigned char* hex){
    unsigned char c = *hex;
    unsigned char t=0;
    if (c >= '0' && c <= '9') {
        t += c - '0';
    } else if (c >= 'A' && c <= 'F') {
        t += c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        t += c - 'a' + 10;
    }
    t = t << 4;
    c = *(hex+1);
    if (c >= '0' && c <= '9') {
        t += c - '0';
    } else if (c >= 'A' && c <= 'F') {
        t += c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        t += c - 'a' + 10;
    }
    return t;
}


int main(int argc, char** argv) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    int fds[2];
    pipe2(fds, O_DIRECT);
    // we make the pipe buffer 4K
    fcntl(fds[0], F_SETPIPE_SZ, 0x1000);
    fcntl(fds[1], F_SETPIPE_SZ, 0x1000);
    
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);


    //seccomp-tools asm -f c_source filter2.seccomp
    static unsigned char filter[] = {32,0,0,0,4,0,0,0,21,0,0,15,62,0,0,192,32,0,0,0,0,0,0,0,53,0,13,0,0,0,0,64,21,0,11,0,35,0,0,0,21,0,10,0,231,0,0,0,21,0,9,0,1,0,0,0,21,0,8,0,0,0,0,0,21,0,7,0,3,0,0,0,21,0,6,0,11,0,0,0,21,0,7,0,9,0,0,0,21,0,6,0,10,0,0,0,21,0,5,0,56,0,0,0,21,0,4,0,16,0,0,0,21,0,3,0,2,0,0,0,6,0,0,0,0,0,0,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0,6,0,0,0,0,0,240,127};
    struct prog {
    unsigned short len;
    unsigned char *filter;
    } rule = {
    .len = sizeof(filter) >> 3,
    .filter = filter
    };
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); exit(2); }
    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) { perror("prctl(PR_SET_SECCOMP)"); exit(2); }
    
    
    unsigned char* otherp = (unsigned char*) mmap((void*)OTHERP, (CODE-OTHERP), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    unsigned char* code = (unsigned char*) mmap((void*)CODE, (STACK-CODE), PROT_READ | PROT_WRITE  | PROT_EXEC, MAP_FIXED |MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    unsigned char* stack = (unsigned char*) mmap((void*)STACK, (STACKEND-STACK), PROT_READ | PROT_WRITE, MAP_FIXED |MAP_SHARED | MAP_ANONYMOUS, -1, 0);


    for(unsigned int i=0; i<(CODE-OTHERP); i++){
        otherp[i]='\x90';
    }
    for(unsigned int i=0; i<(STACK-CODE); i++){
        code[i]='\x90';
    }
    for(unsigned int i=0; i<(STACKEND-STACK); i++){
        stack[i]='\x00';
    }

    for(unsigned int i=0; i<asm_otherp_len; i++){
        otherp[i]=asm_otherp[i];
    }
    for(unsigned int i=0; i<asm_pre_len; i++){
        (CODE)[i]=asm_pre[i];
    }
    for(unsigned int i=0; i<asm_plus_len; i++){
        (FUNCTIONS)[0x0+i]=asm_plus[i];
    }
    for(unsigned int i=0; i<asm_minus_len; i++){
        (FUNCTIONS)[0x100+i]=asm_minus[i];
    }
    for(unsigned int i=0; i<asm_mul_len; i++){
        (FUNCTIONS)[0x200+i]=asm_mul[i];
    }
    for(unsigned int i=0; i<asm_div_len; i++){
        #ifndef DEBUG
        (FUNCTIONS)[0x300+i]=asm_div[i];
        #else
        (FUNCTIONS)[0x300+i]=asm_debugdiv[i];
        #endif
    }
    for(unsigned int i=0; i<asm_epilogue_len; i++){
        (FUNCTIONS)[0x400+i]=asm_epilogue[i];
    }
    for(unsigned int i=0; i<asm_exit_len; i++){
        (EXITF)[i]=asm_exit[i];
    }

    for(unsigned int i=0; i<(strlen(argv[1])/2); i++){
        (GCODE)[i]=hex2bin((unsigned char*)&(argv[1][i*2]));
    }

    for(unsigned int i=0; i<10; i++){
        ((unsigned long*)(VARS))[i] = strtoul(argv[3+i], NULL, 10);
    }


    mprotect((void*)OTHERP, (CODE-OTHERP), PROT_READ | PROT_EXEC);
    mprotect((void*)CODE, (STACK-CODE), PROT_READ  | PROT_EXEC);

    memcpy((STACKEND-0x20), argv[2], 7);

    unsigned long* timevars = ((unsigned long*)(STACKEND-0x20));
    timevars -= 1;
    timevars -= 1;

    *timevars = 1;
    timevars -= 1;
    *timevars = 0;
    timevars -= 1;

    *timevars = 10;
    timevars -= 1;
    *timevars = 0;
    timevars -= 1;

    *timevars = 1000000;
    timevars -= 1;
    *timevars = 0;
    timevars -= 1;


    //https://github.com/spotify/linux/blob/master/include/linux/sched.h
    asm volatile (
        ".intel_syntax noprefix\n"
        "mov rax, 56\n"
        //0x5af00 adds CLONE_PARENT, maybe needed?
        "mov rdi, 0x52f00\n" //CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PTRACE|CLONE_THREAD|CLONE_SYSVSEM
        "mov rsi, rsp\n"
        "mov rdx, 0x1002210\n" //STACKBOTTOM (random locations between STACK and vars)
        "mov r10, 0x1002230\n" //STACKBOTTOM 
        "mov r8, 0x1002250\n" //STACKBOTTOM 
        "syscall\n"
        "test rax, rax\n"
        "jne _out\n"
        "mov rcx, 0x1000000\n" //OTHERP
        "jmp rcx\n"
        "_out:\n"
        "nop\n"
    );


    ((void(*)())(CODE))();

}

