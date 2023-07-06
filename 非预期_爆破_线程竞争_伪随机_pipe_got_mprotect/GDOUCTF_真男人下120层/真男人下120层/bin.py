from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


io=remote("node5.anna.nssctf.cn",28438)
# io=process("./bin")
cs=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")						
cs.srand(0xA5462D92)																					

# gdb.attach(io)
# pause()

for i in range(120):
    io.recvuntil(b"\n")
    payload=cs.rand()%4+1
    io.sendline(str(payload))

io.interactive()