#!/usr/bin/env python

import subprocess
import shutil
import os
import time
import os
import stat
import sys
import hashlib


def run_cmd(args, timeout=None, shell=False, autoerror=True):
    global last_child

    if timeout != None:
        fargs = ["/usr/bin/timeout", "-k", "1", str(timeout)] + args
    else:
        fargs = args
    pipe = subprocess.PIPE

    ntime = time.time()
    p = subprocess.Popen(fargs, stdout=pipe, stderr=pipe, shell=shell)
    last_child = p.pid
    stdout, stderr = p.communicate()
    etime = time.time() - ntime
    rc = p.returncode
    p.wait()
    last_child = None
    if autoerror and rc!=0:
        print("CMD:" + " ".join(fargs))
        print("STDOUT")
        print(stdout.decode('utf-8'))
        print("STDERR")
        print(stderr.decode('utf-8'))
        print("CMD: " + str(rc))

    return (stdout, stderr, rc, etime)



try:
    os.unlink("stub")
except OSError:
    pass
try:
    os.unlink("asm.h")
except OSError:
    pass

with open("asm.h", "wb") as out:
    for f in os.listdir("."):
        if f.endswith(".asm"):
            bname = f[:-4]+".bin"
            try:
                os.unlink(bname)
            except OSError:
                pass
            _, _, rc, _ = run_cmd(("nasm -o %s %s" % (bname, f)), shell=True)
            if rc!=0:
                print("NASM ERROR!")
                sys.exit(2)
            if "payload" in bname:
                continue
            with open(bname, "rb") as fd:
                content = fd.read()
                out.write(b"\n")
                dd = b", ".join([bytes(hex(c), 'utf-8') for c in content])
                tstr = b"unsigned char %s[] = {%s};\n" % (b"asm_"+f[:-4].encode("utf-8"), dd)
                tstr += b"unsigned int %s = %d;\n" % (b"asm_"+f[:-4].encode("utf-8")+b"_len", len(content))
                out.write(tstr+b"\n")


eflag = ""
s, e, rc, _ = run_cmd(("clang "+eflag+" -O2 -o stub stub.c").split())
if rc!=0:
    sys.exit(1)
print(s.decode("utf-8"),"\n",e.decode("utf-8"))
_, _, rc, _ = run_cmd("strip --strip-all  stub".split())
if rc!=0:
    sys.exit(2)


run_cmd("rm -r __pycache__", shell=True, autoerror=False)
run_cmd("python -m py_compile ./supersafecalc.py".split())

fname = [os.path.join("__pycache__/", n) for n in os.listdir("__pycache__/") if "supersafecalc" in n][0]

shutil.copy2(fname, "./supersafecalc.pyc")
run_cmd("rm -r __pycache__", shell=True, autoerror=False)


print("DONE")


