from pwn import *

payload=cyclic(0x300)

with open("payload","w") as f:
    f.write(payload.decode())
