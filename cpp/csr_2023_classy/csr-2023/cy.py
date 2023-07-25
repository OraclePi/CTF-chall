from pwn import *
import tty
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("rumble.host",9797)
# io=process("./classy")

io.recvuntil(b"level?\n")
io.sendline(b"2")
io.recvuntil(b"password:\n")
io.sendline('55aefb4ca5630cc73a981e9d642324fc')
io.recvuntil(b"level.\n")
io.sendline(b"3")
io.recvuntil(b"me?\n")
io.sendline(b"1")

io.interactive()