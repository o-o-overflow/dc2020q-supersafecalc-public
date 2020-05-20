#!/usr/bin/env python

import struct
import random
import string
import subprocess
import os
import sys
import hashlib
from collections import defaultdict

import resource

from pyparsing import (
    Literal,
    Word,
    Group,
    Forward,
    alphas,
    alphanums,
    Regex,
    Suppress,
)

#from: https://github.com/cloudburst/pyptrace/blob/master/defines.py
PTRACE_TRACEME = 0 
#   Return the word in the process's text space at address ADDR.  
PTRACE_PEEKTEXT = 1 
#   Return the word in the process's data space at address ADDR.  
PTRACE_PEEKDATA = 2 
#   Return the word in the process's user area at offset ADDR.  
PTRACE_PEEKUSER = 3 
#   Write the word DATA into the process's text space at address ADDR.  
PTRACE_POKETEXT = 4 
#   Write the word DATA into the process's data space at address ADDR.  
PTRACE_POKEDATA = 5 
#   Write the word DATA into the process's user area at offset ADDR.  
PTRACE_POKEUSER = 6 
#   Continue the process.  
PTRACE_CONT = 7 
#   Kill the process.  
PTRACE_KILL = 8 
#   Single step the process.
#     This is not supported on all machines.  
PTRACE_SINGLESTEP = 9
#  Get all general purpose registers used by a processes.
#     This is not supported on all machines.  
PTRACE_GETREGS = 12
#   Set all general purpose registers used by a processes.
#     This is not supported on all machines.  
PTRACE_SETREGS = 13
#   Get all floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_GETFPREGS = 14
#   Set all floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_SETFPREGS = 15
#   Attach to a process that is already running. 
PTRACE_ATTACH = 16
#   Detach from a process attached to with PTRACE_ATTACH.  
PTRACE_DETACH = 17
#   Get all extended floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_GETFPXREGS = 18
#   Set all extended floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_SETFPXREGS = 19
#   Continue and stop at the next (return from) syscall.  
PTRACE_SYSCALL = 24


#   Set ptrace filter options.  
PTRACE_SETOPTIONS  = 0x4200
#   Get last ptrace message.  
PTRACE_GETEVENTMSG = 0x4201
#   Get siginfo for process.  
PTRACE_GETSIGINFO  = 0x4202
#   Set new siginfo for process.  
PTRACE_SETSIGINFO  = 0x4203

PTRACE_LISTEN = 0x4208


#  Options set using PTRACE_SETOPTIONS.
PTRACE_O_TRACESYSGOOD   = 0x00000001
PTRACE_O_TRACEFORK      = 0x00000002
PTRACE_O_TRACEVFORK     = 0x00000004
PTRACE_O_TRACECLONE     = 0x00000008
PTRACE_O_TRACEEXEC      = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT      = 0x00000040
PTRACE_O_MASK           = 0x0000007f
PTRACE_O_TRACESECCOMP   = 0x00000080
PTRACE_O_EXITKILL       = 0x00100000
PTRACE_O_SUSPEND_SECCOMP= 0x00200000


PTRACE_SEIZE       = 0x4206

import ctypes
from ctypes import *
from ctypes import get_errno, cdll 
from ctypes.util import find_library

class user_regs_struct(Structure):
    _fields_ = (
        ("r15", c_ulong),
        ("r14", c_ulong),
        ("r13", c_ulong),
        ("r12", c_ulong),
        ("rbp", c_ulong),
        ("rbx", c_ulong),
        ("r11", c_ulong),
        ("r10", c_ulong),
        ("r9", c_ulong),
        ("r8", c_ulong),
        ("rax", c_ulong),
        ("rcx", c_ulong),
        ("rdx", c_ulong),
        ("rsi", c_ulong),
        ("rdi", c_ulong),
        ("orig_rax", c_ulong),
        ("rip", c_ulong),
        ("cs", c_ulong),
        ("eflags", c_ulong),
        ("rsp", c_ulong),
        ("ss", c_ulong),
        ("fs_base", c_ulong),
        ("gs_base", c_ulong),
        ("ds", c_ulong),
        ("es", c_ulong),
        ("fs", c_ulong),
        ("gs", c_ulong)
    )

libc = CDLL("libc.so.6", use_errno=True)
ptrace = libc.ptrace
ptrace.argtypes = [c_uint, c_uint, c_long, c_long]
ptrace.restype = c_long


#changing these requires changing stuff in stub.c and in the asm files
CODE        = 0x1001000
FUNCTIONS   = 0x1001100 #+, -, *, /, epilogue
EXITF       = 0x1001600
GCODE       = 0x1001700
STACK       = 0x1002000
VARS        = 0x1002f00
STACKBOTTOM = 0x1002200
STACKEND    = 0x1003000

syscall_table = ['read', 'write', 'open', 'close', 'stat', 'fstat', 'lstat', 'poll', 'lseek', 'mmap', 'mprotect', 'munmap', 'brk', 'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'ioctl', 'pread64', 'pwrite64', 'readv', 'writev', 'access', 'pipe', 'select', 'sched_yield', 'mremap', 'msync', 'mincore', 'madvise', 'shmget', 'shmat', 'shmctl', 'dup', 'dup2', 'pause', 'nanosleep', 'getitimer', 'alarm', 'setitimer', 'getpid', 'sendfile', 'socket', 'connect', 'accept', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'shutdown', 'bind', 'listen', 'getsockname', 'getpeername', 'socketpair', 'setsockopt', 'getsockopt', 'clone', 'fork', 'vfork', 'execve', 'exit', 'wait4', 'kill', 'uname', 'semget', 'semop', 'semctl', 'shmdt', 'msgget', 'msgsnd', 'msgrcv', 'msgctl', 'fcntl', 'flock', 'fsync', 'fdatasync', 'truncate', 'ftruncate', 'getdents', 'getcwd', 'chdir', 'fchdir', 'rename', 'mkdir', 'rmdir', 'creat', 'link', 'unlink', 'symlink', 'readlink', 'chmod', 'fchmod', 'chown', 'fchown', 'lchown', 'umask', 'gettimeofday', 'getrlimit', 'getrusage', 'sysinfo', 'nfo', 'times', 'nfo', 'ptrace', 'getuid', 'syslog', 'getgid', 'setuid', 'setgid', 'geteuid', 'getegid', 'setpgid', 'getppid', 'getpgrp', 'setsid', 'setreuid', 'setregid', 'getgroups', 'setgroups', 'setresuid', 'getresuid', 'setresgid', 'getresgid', 'getpgid', 'setfsuid', 'setfsgid', 'getsid', 'capget', 'capset', 'rt_sigpending', 'rt_sigtimedwait', 'rt_sigqueueinfo', 'rt_sigsuspend', 'sigaltstack', 'utime', 'mknod', 'uselib', 'personality', 'ustat', 'statfs', 'fstatfs', 'sysfs', 'getpriority', 'setpriority', 'sched_setparam', 'sched_getparam', 'sched_setscheduler', 'sched_getscheduler', 'sched_get_priority_max', 'sched_get_priority_min', 'sched_rr_get_interval', 'mlock', 'munlock', 'mlockall', 'munlockall', 'vhangup', 'modify_ldt', 'pivot_root', '_sysctl', 'sctl_args', 'prctl', 'arch_prctl', 'adjtimex', 'setrlimit', 'chroot', 'sync', 'acct', 'settimeofday', 'mount', 'umount2', 'swapon', 'swapoff', 'reboot', 'sethostname', 'setdomainname', 'iopl', 'ioperm', 'create_module', 'init_module', 'delete_module', 'get_kernel_syms', 'query_module', 'quotactl', 'nfsservctl', 'getpmsg', 'putpmsg', 'afs_syscall', 'tuxcall', 'security', 'gettid', 'readahead', 'setxattr', 'lsetxattr', 'fsetxattr', 'getxattr', 'lgetxattr', 'fgetxattr', 'listxattr', 'llistxattr', 'flistxattr', 'removexattr', 'lremovexattr', 'fremovexattr', 'tkill', 'time', 'futex', 'sched_setaffinity']


def pkiller():
    from ctypes import cdll
    import ctypes
    # PR_SET_PDEATHSIG, SIG_KILL --> kill child when parent dies
    cdll['libc.so.6'].prctl(1, 9)


def readuntil(fd, tstr):
    buf = b""
    while True:
        buf += os.read(fd, 1)
        if buf.endswith(tstr):
            break
    return buf


def writen(fd, buf, pos=-1):
    if pos >= 0:
        os.lseek(fd, pos, 0) #SEEK_SET
    while True:
        nw = os.write(fd, buf)
        buf = buf[nw:]
        if buf == b"":
            break

def readmem(pid, pos=-1, tlen=8):
    fd=os.open("/proc/%d/mem" % pid, os.O_RDONLY)
    if pos >= 0:
        os.lseek(fd, pos, 0) #SEEK_SET
    buf = b""
    while True:
        cd = os.read(fd, tlen-len(buf))
        if(cd==b""):
            break
        buf += cd
        if len(buf)==tlen:
            break
    return buf


def rnd_str(tlen=8):
    letters = (string.ascii_lowercase + string.ascii_uppercase + string.digits).encode("utf-8")
    return b"".join(random.choice(letters) for i in range(tlen))


# from the original pyparsing BNF example
class BNFP:
    parser = None
    exprStack = []

    def __init__(self):
        exprStack = []
        fnumber = Regex(r"\d{1,10}").setName('number')
        variable = Regex(r"v\d").setName('variable')

        plus, minus, mult, div = map(Literal, "+-*/")
        lpar, rpar = map(Suppress, "()")
        addop = plus | minus
        multop = mult | div
        addop.setName('op')
        multop.setName('op')

        expr = Forward()

        atom = (
            addop[...]
            + (
                (variable).setParseAction(lambda x:self.exprStack.append((x[0], "var")))
                | (fnumber).setParseAction(lambda x:self.exprStack.append((x[0], "num")))
                | Group(lpar + expr + rpar)
            )
        )

        factor = Forward()
        factor <<= atom
        term = factor + (multop + factor).setParseAction(lambda x:self.exprStack.append((x[0], "op")))[...]
        expr <<= term + (addop + term).setParseAction(lambda x:self.exprStack.append((x[0], "op")))[...]
        bnf = expr
        self.parser = bnf

    def parse(self, tstr):
        tstr = tstr.replace(b" ",b"")
        if any([c not in b"1234567890+-*/()v" for c in tstr]):
            return None, None
        utstr = tstr.decode("utf-8")
        self.exprStack = []
        res = self.parser.parseString(utstr)
        return res, self.exprStack


def parse_status(status):
    def num_to_sig(num):
        sigs = ["SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS"]
        if num-1 < len(sigs):
            return sigs[num-1]
        else:
            return hex(num)[2:]


    status_list = []
    status_list.append(hex(status))
    ff = [os.WCOREDUMP, os.WIFSTOPPED, os.WIFSIGNALED, os.WIFEXITED, os.WIFCONTINUED]
    for f in ff:
        if f(status):
            status_list.append(f.__name__)
            break
    else:
        status_list.append("")
    status_list.append(num_to_sig((status>>8)&0xff))
    ss = (status & 0xff0000) >> 16
    ptrace_sigs = ["PTRACE_EVENT_FORK", "PTRACE_EVENT_VFORK", "PTRACE_EVENT_CLONE", "PTRACE_EVENT_EXEC", "PTRACE_EVENT_VFORK_DONE", "PTRACE_EVENT_EXIT", "PTRACE_EVENT_SECCOMP"]
    if ss >= 1 and ss-1 <= len(ptrace_sigs):
        status_list.append(ptrace_sigs[ss-1])
    else:
        status_list.append(hex(ss)[2:])
    return status_list


def write(buf):
    sys.stdout.buffer.write(buf)
    sys.stdout.buffer.flush()


def main(pfname):
    resource.setrlimit(resource.RLIMIT_STACK, (50000000,50000000))
    resource.setrlimit(resource.RLIMIT_DATA, (150000000,150000000))

    pfname = pfname.encode("utf-8")
    if len(pfname) != 7:
        return 4

    try:
        os.unlink(pfname)
    except OSError:
        pass

    write(b"Welcome to the safest possible calculator!\n")
    write(b"Powered by OOO and modern Linux technology\n")
    write(b"\n")

    write(b"Send me your math expression (to be safe, I only support +, -, *, /):\n")


    line = next(sys.stdin.buffer)
    if len(line) > 2500:
        write(b"Too long\n")
        return 3

    line = line.strip()
    #"OOO_v3ry_secret_backdoor_for_hashes_OOO"
    if hashlib.sha256(line).hexdigest() == '5ae2651d8876e3745381383fb265ac7fac7923ed5ca4099f39d19bfa6fe8a04c':
        with open(__file__, "rb") as fp:
            ccc = fp.read()
            s = hashlib.sha256(ccc).hexdigest().encode("utf-8")+b"\n"
            write(s)
        with open("stub", "rb") as fp:
            ccc = fp.read()
            s = hashlib.sha256(ccc).hexdigest().encode("utf-8")+b"\n"
            write(s)
        return 7

    tstr2 = line

    intvars = []
    for i in range(10):
        write(b"Give me the value of v"+str(i).encode("utf-8")+b":\n")
        line = next(sys.stdin.buffer)
        try:
            v = int(line)
        except ValueError:
            write(b"Invalid number\n")
            return 3
        if v<0 or v>=pow(2,64):
            write(b"Invalid number\n")
            return 3
        intvars.append(v)


    pp = BNFP()
    sys.setrecursionlimit(100000)

    r, t = pp.parse(tstr2)
    if r == None:
        write(b"Invalid expression\n")
        return 3

    write(b"Computing...\n")

    code = b"" 
    for v, ttype in t:
        #print(v, ttype)
        if ttype == "num":
            # mov rbx, num
            # push rbx
            code += bytes.fromhex("48bb") + struct.pack("<Q", int(v,10))
            code += b"\x53"
        elif ttype == "var":
            varindex = int(v[1], 10)
            # mov rbx, VAR+0x10*varindex
            # mov rbx, qword ptr [rbx]
            # push rbx
            code += bytes.fromhex("48bb") + struct.pack("<Q", VARS+0x8*varindex)
            code += bytes.fromhex("488b1b")
            code += b"\x53"
        elif ttype == "op":
            ffstr = "+-*/"
            findex = ffstr.index(v)
            # mov rcx, FUNCTIONS+(findex*0x100)
            # call rcx
            code += bytes.fromhex("48b9") + struct.pack("<Q", FUNCTIONS+(findex*0x100))
            code += bytes.fromhex("ffd1")

    code += bytes.fromhex("48b9") + struct.pack("<Q", EXITF) # mov rcx, EXITF
    code += bytes.fromhex("ffe1") # jmp rcx

    ccode = code[:STACK-GCODE] # bug! allow to arrive at the end so that the last 8 bytes can be used as stack and can be controlled 


    vvars = [str(v) for v in intvars]
    args = [ccode.hex(), pfname.decode("utf-8")] + vvars

    pipe = subprocess.PIPE
    fullargs = ["./stub"] + args

    p = subprocess.Popen(fullargs, stdout=pipe, stderr=pipe, close_fds=True, preexec_fn=pkiller)
    pid = p.pid
    opid = pid
    #print(p, pid)
    pid, status = os.waitpid(-1, 0) # this will wait for the raise added at the beginning of the child

    #the following MUST happen after the child called tracme, but before it continues
    #therefore, the waitpid above is essential to call SETOPTIONS while the child is not terminated yet, but it has called traceme
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK)
    ptrace(PTRACE_CONT, pid, 0, 0)

    allowed_syscall_instances = {'mprotect': 2, 'clone': 1, 'mmap': 4} #bug! mmap should be 3
    regs = user_regs_struct()
    while(True):
        pid, status = os.waitpid(-1, 0) # there is a problem here, if a child dies because of seccomp kill, waitpid does not catch that
        parsed_status = parse_status(status)
        #print("P" if pid == opid else "S", pid, "|".join(parsed_status))
        if parsed_status[1] == "WIFEXITED":
            break

        if parsed_status[2] == "SIGSEGV":
            #ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
            #print(hex(regs.rip), hex(regs.rsp), hex(regs.rcx), hex(regs.rax))
            #import IPython; IPython.embed();
            break

        if parsed_status[3] == "PTRACE_EVENT_SECCOMP":
            res = ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
            syscall_number = regs.orig_rax
            syscall_name = syscall_table[regs.orig_rax] if regs.orig_rax < len(syscall_table) else "unk"
            #print("    >", syscall_number, syscall_name)

            if syscall_name in allowed_syscall_instances:
                allowed_syscall_instances[syscall_name] -= 1
                if allowed_syscall_instances[syscall_name] < 0:
                    #print("Too many syscalls!")
                    regs.orig_rax = -1
                    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))

            elif syscall_name == "ioctl":
                if regs.rsi != 0x541B: # used to get pipe size
                    #print("Invalid syscall argument (ioctl, 1)!")
                    regs.orig_rax = -1
                    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))

                if regs.rdi != 4:
                    #print("Invalid syscall argument (ioctl, 2)!")
                    regs.orig_rax = -1
                    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))

            elif syscall_name == "open":
                #bug! nothing guarantees that the file name stays the same between the time Python checks it and the time the syscall is actually done
                if regs.rdx != 0o777: # we can only open with 777
                    #print("Invalid syscall argument (open, 1)!")
                    regs.orig_rax = -1
                    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
                    

                else:         
                    fd=os.open("/proc/%d/mem" % pid, os.O_RDONLY)
                    os.lseek(fd, regs.rdi, os.SEEK_SET)
                    fname = readuntil(fd, b"\x00")
                    fname = fname[:-1]
                    os.close(fd)
                    #print(">|"+repr(fname)+"|<")
                    if fname != pfname:
                        #print("Invalid syscall argument (open, 2)!")
                        regs.orig_rax = -1
                        ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))

            else:
                #print("Unknown syscall!")
                regs.orig_rax = -1
                ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))

        if parsed_status[2] == "SIGFPE":
            res = ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))

            if regs.rbp == 0:
                regs.rax = 0

                #simulate what the rest of div.asm does, setting 0 as the result
                #push rax --> mov [rsp], rax
                fd=os.open("/proc/%d/mem" % pid, os.O_RDWR)
                #os.lseek(fd, regs.rsp-8, os.SEEK_SET)
                #print(repr(os.read(fd, 8)))
                writen(fd, struct.pack("<Q", regs.rax), regs.rsp-8)
                os.close(fd)
                #push rax --> sub rsp, 8
                regs.rsp -= 8
                #add rsp, 0x10
                regs.rsp += 0x10

            # bug! if not div by 0, we end up simulating div.asm wrongly
            regs.rip = FUNCTIONS+(0x100*4)
            ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))


        res = ptrace(PTRACE_CONT, pid, 0, 0)
        #print(pid, res)

    #print(repr(allowed_syscall_instances))
    try:
        p.kill()
    except OSError:
        pass
    #res = p.communicate()
    #the following is basically like p.wait(), but waits for all threads, therefore it does not stall
    while True:
        try:
            pid, status = os.waitpid(-1, 0)
            parsed_status = parse_status(status)
            #print("P" if pid == opid else "S", pid, "|".join(parsed_status))
        except ChildProcessError:
            break

    with open(pfname, "rb") as fp:
        content = fp.read()
        v = struct.unpack("<Q", content.ljust(8,b'\x00')[:8])[0]
        #print("===>", v, hex(v), repr(content), repr(struct.pack("<Q", v)))

        write(b"Result:\n")
        write(str(v).encode("utf-8")+b"\n")
        write(b"Goodbye!\n")


    try:
        os.unlink(pfname)
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

